"""Core authentication logic for password and SSO flows.

Handles credential verification, SSO claim extraction, user provisioning,
and automatic account merging. All public entry points accept an
:class:`~authshield.config.AuthConfig` instance and return an optional
:class:`~authshield.auth.models.UserSession`.
"""

from __future__ import annotations

import secrets
import uuid
from typing import TYPE_CHECKING, Optional

from authshield.auth._hashing import verify_password
from authshield.auth.models import UserSession, UserUpdate

if TYPE_CHECKING:
    from authshield.config import AuthConfig


USERNAME_PART_A = ["cool", "super", "hyper", "funny", "silly", "witty", "brave", "clever", "fancy", "lucky"]
USERNAME_PART_B = ["tiger", "eagle", "panda", "ninja", "pirate", "wizard", "robot", "unicorn", "samurai", "dragon"]


def _generate_username() -> str:
    """Return a random two-part username (e.g. "brave dragon")."""
    return secrets.choice(USERNAME_PART_A) + " " + secrets.choice(USERNAME_PART_B)


def _extract_name(claims: dict) -> str:
    """Extract a human-readable display name from SSO claims.

    Tries, in order: ``name``, ``given_name`` + ``family_name``,
    ``preferred_username``, ``nickname``, ``display_name``, the local part
    of ``email``, and finally falls back to ``SSO_User_<id>``.

    Parameters
    ----------
    claims : dict
        The decoded claims from the SSO identity provider.

    Returns
    -------
    str
        The best available display name.
    """
    email = claims.get("email")
    first_name = claims.get("given_name")
    last_name = claims.get("family_name")
    combined_name = f"{first_name} {last_name}".strip() if (first_name or last_name) else None

    name_options = [
        claims.get("name"),
        combined_name,
        claims.get("preferred_username"),
        claims.get("nickname"),
        claims.get("display_name"),
        email.split("@")[0] if email else None,
    ]

    name = next((str(val).strip() for val in name_options if val), None)

    if not name:
        sso_sub = claims.get("sub")
        suffix = sso_sub[:8] if sso_sub else uuid.uuid4().hex[:8]
        name = f"SSO_User_{suffix}"

    return name


def _resolve_roles(claims: dict, config: AuthConfig) -> list:
    """Map SSO claim roles to application roles via the configured mapping.

    Parameters
    ----------
    claims : dict
        The decoded claims from the SSO identity provider.
    config : AuthConfig
        Active authentication configuration containing the SSO role mapping.

    Returns
    -------
    list
        Resolved application roles (includes the default role when set).
    """
    claim_roles = claims.get("roles") or claims.get("groups") or []
    default = config.sso_config.default_role
    assigned_roles = [default] if default is not None else []

    for role_name, role in config.sso_config.role_mapping.items():
        if role_name in claim_roles:
            assigned_roles.append(role)

    return assigned_roles


async def authenticate_user(email: str, password: str, config: AuthConfig) -> Optional[UserSession]:
    """Authenticate a user with email and password.

    Looks up the user via ``config.get_user``, verifies the password hash,
    and returns a session on success.

    Parameters
    ----------
    email : str
        The user's email address.
    password : str
        Plain-text password to verify.
    config : AuthConfig
        Active authentication configuration.

    Returns
    -------
    Optional[UserSession]
        A new session on successful authentication, or ``None`` if the user
        is missing, inactive, or the password is incorrect.
    """
    user = await config.get_user(email)

    if user is None or user.password_hash is None:
        return None

    if not user.active:
        return None

    if verify_password(user.password_hash, password):
        return UserSession(session_token=secrets.token_urlsafe(32), user=user.user)

    return None


async def _handle_existing_email_user(
    claims: dict,
    email_user,
    name: str,
    config: AuthConfig,
) -> Optional[UserSession]:
    """Handle SSO login when a local user with the same email already exists.

    Two cases are handled:

    1. **Merging** -- the local user has a password hash and
       ``auto_merging_enabled`` is ``True``: the SSO ``sub`` is linked to
       the existing account.
    2. **Activation** -- the local user has no password hash (SSO-only
       provisioned): the account is updated with SSO details and roles.

    Parameters
    ----------
    claims : dict
        Decoded SSO claims.
    email_user : UserEntry
        The existing local user matched by email.
    name : str
        Display name extracted from the SSO claims.
    config : AuthConfig
        Active authentication configuration.

    Returns
    -------
    Optional[UserSession]
        A new session if the merge/update succeeds, or ``None`` when the
        existing user already has a password hash and merging is disabled.
    """
    sso_sub = claims.get("sub")

    if email_user.password_hash is not None and config.sso_config.auto_merging_enabled:
        updated_user = await config.sso_config.update_or_create_user(UserUpdate(sub=sso_sub, id=email_user.id))
        return UserSession(session_token=secrets.token_urlsafe(32), user=updated_user.user)

    if email_user.password_hash is None:
        username = claims.get("preferred_username") or claims.get("name") or _generate_username()
        roles = _resolve_roles(claims, config)

        await config.sso_config.update_or_create_user(UserUpdate(
            sub=sso_sub,
            id=email_user.id,
            username=username,
            full_name=name,
            roles=roles,
        ))
        return UserSession(session_token=secrets.token_urlsafe(32), user=email_user.user)

    return None


async def _provision_new_user(
    claims: dict,
    name: str,
    config: AuthConfig,
) -> Optional[UserSession]:
    """Create a brand-new local user from SSO claims.

    Only runs when ``auto_provisioning_enabled`` is ``True`` on the SSO
    configuration; otherwise returns ``None``.

    Parameters
    ----------
    claims : dict
        Decoded SSO claims.
    name : str
        Display name extracted from the SSO claims.
    config : AuthConfig
        Active authentication configuration.

    Returns
    -------
    Optional[UserSession]
        A new session for the provisioned user, or ``None`` when auto-
        provisioning is disabled.
    """
    if not config.sso_config.auto_provisioning_enabled:
        return None

    email = claims.get("email")
    sso_sub = claims.get("sub")
    username = claims.get("preferred_username") or claims.get("name") or _generate_username()
    roles = _resolve_roles(claims, config)

    user_entry = await config.sso_config.update_or_create_user(UserUpdate(
        email=email or "",
        username=username,
        full_name=name,
        sub=sso_sub,
        roles=roles,
    ))

    return UserSession(session_token=secrets.token_urlsafe(32), user=user_entry.user)


async def authenticate_user_by_sso(claims: dict, config: AuthConfig) -> Optional[UserSession]:
    """Authenticate or provision a user from SSO identity provider claims.

    Resolution order:

    1. Match by SSO ``sub`` (return existing session if found).
    2. Match by email -- delegate to :func:`_handle_existing_email_user`.
    3. Auto-provision a new user via :func:`_provision_new_user`.

    Parameters
    ----------
    claims : dict
        Decoded claims from the SSO identity provider.
    config : AuthConfig
        Active authentication configuration.

    Returns
    -------
    Optional[UserSession]
        A new session on success, or ``None`` when the user is inactive,
        no provisioning strategy matches, or auto-provisioning is disabled.
    """
    sso_sub = claims.get("sub")

    user = await config.sso_config.get_user_by_sub(sso_sub)
    if user:
        if not user.active:
            return None
        
        # TODO: Update the user roles here if update_roles_on_login is enabled?
        
        return UserSession(session_token=secrets.token_urlsafe(32), user=user.user)

    name = _extract_name(claims)

    email = claims.get("email")
    if email:
        email_user = await config.get_user(email)
        if email_user is not None:
            if not email_user.active:
                return None

            return await _handle_existing_email_user(claims, email_user, name, config)

    return await _provision_new_user(claims, name, config)
