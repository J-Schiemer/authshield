"""Unit tests for the update_roles_on_login feature."""

from __future__ import annotations

from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from authshield.auth._auth_handler import authenticate_user_by_sso, _resolve_roles
from authshield.auth.models import UserEntry, UserSession, UserUpdate
from authshield.config import AuthConfig, AuthEndpointConfig, SsoConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user_entry(
    *,
    id: Any = "user-1",
    user: Any = "app-user",
    sub: str = "sso-sub-1",
    active: bool = True,
    password_hash: Optional[str] = None,
) -> UserEntry:
    return UserEntry(
        id=id,
        user=user,
        sub=sub,
        active=active,
        password_hash=password_hash,
    )


def _make_config(
    *,
    get_user_by_sub: AsyncMock | None = None,
    update_or_create_user: AsyncMock | None = None,
    update_roles_on_login: bool = False,
    role_mapping: dict[str, Any] | None = None,
    default_role: Any = None,
    auto_provisioning_enabled: bool = False,
    auto_merging_enabled: bool = False,
) -> AuthConfig:
    sso = SsoConfig(
        get_user_by_sub=get_user_by_sub or AsyncMock(return_value=None),
        update_or_create_user=update_or_create_user or AsyncMock(),
        update_roles_on_login=update_roles_on_login,
        role_mapping=role_mapping or {},
        default_role=default_role,
        auto_provisioning_enabled=auto_provisioning_enabled,
        auto_merging_enabled=auto_merging_enabled,
    )
    return AuthConfig(
        sso_enabled=True,
        sso_config=sso,
        auth_endpoint_config=AuthEndpointConfig(),
        get_user=AsyncMock(return_value=None),
        routes_enabled=False,
    )


# ---------------------------------------------------------------------------
# _resolve_roles
# ---------------------------------------------------------------------------


class TestResolveRoles:
    def test_no_roles_in_claims(self):
        config = _make_config(role_mapping={"admin": "superadmin"})
        roles = _resolve_roles({}, config)
        assert roles == []

    def test_roles_from_claims_mapped(self):
        config = _make_config(role_mapping={"admin": "superadmin", "editor": "writer"})
        claims = {"roles": ["admin", "editor"]}
        roles = _resolve_roles(claims, config)
        assert roles == ["superadmin", "writer"]

    def test_groups_fallback(self):
        config = _make_config(role_mapping={"admins": "superadmin"})
        claims = {"groups": ["admins"]}
        roles = _resolve_roles(claims, config)
        assert roles == ["superadmin"]

    def test_unmapped_roles_ignored(self):
        config = _make_config(role_mapping={"admin": "superadmin"})
        claims = {"roles": ["admin", "guest"]}
        roles = _resolve_roles(claims, config)
        assert roles == ["superadmin"]

    def test_default_role_added(self):
        config = _make_config(default_role="viewer")
        claims = {"roles": ["admin"]}
        roles = _resolve_roles(claims, config)
        assert roles == ["viewer"]

    def test_default_role_and_mapped_roles(self):
        config = _make_config(role_mapping={"admin": "superadmin"}, default_role="viewer")
        claims = {"roles": ["admin"]}
        roles = _resolve_roles(claims, config)
        assert roles == ["viewer", "superadmin"]

    def test_no_role_mapping(self):
        config = _make_config()
        claims = {"roles": ["admin"]}
        roles = _resolve_roles(claims, config)
        assert roles == []


# ---------------------------------------------------------------------------
# authenticate_user_by_sso — update_roles_on_login
# ---------------------------------------------------------------------------


class TestUpdateRolesOnLogin:
    @pytest.mark.anyio
    async def test_roles_updated_when_flag_true(self):
        updated_user = _make_user_entry(id="user-1", user="app-user")
        get_user_by_sub = AsyncMock(return_value=_make_user_entry())
        update_or_create_user = AsyncMock(return_value=updated_user)

        config = _make_config(
            get_user_by_sub=get_user_by_sub,
            update_or_create_user=update_or_create_user,
            update_roles_on_login=True,
            role_mapping={"admin": "superadmin"},
        )

        claims = {"sub": "sso-sub-1", "roles": ["admin"]}
        session = await authenticate_user_by_sso(claims, config)

        assert session is not None
        update_or_create_user.assert_awaited_once()
        call_args = update_or_create_user.call_args[0][0]
        assert isinstance(call_args, UserUpdate)
        assert call_args.id == "user-1"
        assert call_args.roles == ["superadmin"]

    @pytest.mark.anyio
    async def test_roles_not_updated_when_flag_false(self):
        get_user_by_sub = AsyncMock(return_value=_make_user_entry())
        update_or_create_user = AsyncMock()

        config = _make_config(
            get_user_by_sub=get_user_by_sub,
            update_or_create_user=update_or_create_user,
            update_roles_on_login=False,
            role_mapping={"admin": "superadmin"},
        )

        claims = {"sub": "sso-sub-1", "roles": ["admin"]}
        session = await authenticate_user_by_sso(claims, config)

        assert session is not None
        update_or_create_user.assert_not_awaited()

    @pytest.mark.anyio
    async def test_roles_updated_with_default_role(self):
        updated_user = _make_user_entry(id="user-1", user="app-user")
        get_user_by_sub = AsyncMock(return_value=_make_user_entry())
        update_or_create_user = AsyncMock(return_value=updated_user)

        config = _make_config(
            get_user_by_sub=get_user_by_sub,
            update_or_create_user=update_or_create_user,
            update_roles_on_login=True,
            default_role="viewer",
            role_mapping={"admin": "superadmin"},
        )

        claims = {"sub": "sso-sub-1", "roles": ["admin"]}
        session = await authenticate_user_by_sso(claims, config)

        assert session is not None
        call_args = update_or_create_user.call_args[0][0]
        assert call_args.roles == ["viewer", "superadmin"]

    @pytest.mark.anyio
    async def test_roles_cleared_when_no_claims_roles(self):
        updated_user = _make_user_entry(id="user-1", user="app-user")
        get_user_by_sub = AsyncMock(return_value=_make_user_entry())
        update_or_create_user = AsyncMock(return_value=updated_user)

        config = _make_config(
            get_user_by_sub=get_user_by_sub,
            update_or_create_user=update_or_create_user,
            update_roles_on_login=True,
        )

        claims = {"sub": "sso-sub-1"}
        session = await authenticate_user_by_sso(claims, config)

        assert session is not None
        call_args = update_or_create_user.call_args[0][0]
        assert call_args.roles == []

    @pytest.mark.anyio
    async def test_inactive_user_returns_none(self):
        get_user_by_sub = AsyncMock(
            return_value=_make_user_entry(active=False)
        )
        update_or_create_user = AsyncMock()

        config = _make_config(
            get_user_by_sub=get_user_by_sub,
            update_or_create_user=update_or_create_user,
            update_roles_on_login=True,
        )

        claims = {"sub": "sso-sub-1", "roles": ["admin"]}
        session = await authenticate_user_by_sso(claims, config)

        assert session is None
        update_or_create_user.assert_not_awaited()

    @pytest.mark.anyio
    async def test_session_returns_updated_user(self):
        original_user = _make_user_entry(id="user-1", user="old-user")
        updated_user = _make_user_entry(id="user-1", user="updated-user")

        get_user_by_sub = AsyncMock(return_value=original_user)
        update_or_create_user = AsyncMock(return_value=updated_user)

        config = _make_config(
            get_user_by_sub=get_user_by_sub,
            update_or_create_user=update_or_create_user,
            update_roles_on_login=True,
            role_mapping={"admin": "superadmin"},
        )

        claims = {"sub": "sso-sub-1", "roles": ["admin"]}
        session = await authenticate_user_by_sso(claims, config)

        assert session is not None
        assert session.user == "updated-user"

    @pytest.mark.anyio
    async def test_session_user_without_roles_when_flag_false(self):
        user = _make_user_entry(id="user-1", user="app-user")
        get_user_by_sub = AsyncMock(return_value=user)
        update_or_create_user = AsyncMock()

        config = _make_config(
            get_user_by_sub=get_user_by_sub,
            update_or_create_user=update_or_create_user,
            update_roles_on_login=False,
            role_mapping={"admin": "superadmin"},
        )

        claims = {"sub": "sso-sub-1", "roles": ["admin"]}
        session = await authenticate_user_by_sso(claims, config)

        assert session is not None
        assert session.user == "app-user"

    @pytest.mark.anyio
    async def test_groups_used_as_fallback_for_roles(self):
        updated_user = _make_user_entry(id="user-1", user="app-user")
        get_user_by_sub = AsyncMock(return_value=_make_user_entry())
        update_or_create_user = AsyncMock(return_value=updated_user)

        config = _make_config(
            get_user_by_sub=get_user_by_sub,
            update_or_create_user=update_or_create_user,
            update_roles_on_login=True,
            role_mapping={"admins": "superadmin"},
        )

        claims = {"sub": "sso-sub-1", "groups": ["admins"]}
        session = await authenticate_user_by_sso(claims, config)

        assert session is not None
        call_args = update_or_create_user.call_args[0][0]
        assert call_args.roles == ["superadmin"]
