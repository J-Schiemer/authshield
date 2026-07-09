"""Data models used throughout the authentication layer.

All models are Pydantic ``BaseModel`` subclasses, so they support
serialization, validation, and ``model_copy`` semantics out of the box.
"""

from typing import Any, Optional

from pydantic import BaseModel


class UserSession(BaseModel):
    """Represents an authenticated user session.

    Attributes
    ----------
    session_token : str
        Opaque, high-entropy token used as the session identifier.
    user : Any
        The application-defined user object associated with this session.
    roles : Optional[list[Any]]
        Roles granted to the user for the current session, if any.
    """

    session_token: str
    user: Any
    roles: Optional[list[Any]]


class UserEntry(BaseModel):
    """Internal user record stored by the authentication backend.

    Attributes
    ----------
    password_hash : Optional[str]
        Argon2id hash of the user's password, or ``None`` for SSO-only
        accounts.
    user : Any
        The application-defined user object exposed to session consumers.
    active : bool
        Whether the account is active. Inactive users cannot authenticate.
        Defaults to ``True``.
    provisioned : bool
        ``True`` when the account was auto-created by an SSO provider.
        Defaults to ``True``.
    id : Any
        Internal unique identifier for the user record.
    sub : Optional[str]
        SSO subject identifier linking this account to an external
        identity provider, or ``None`` for password-only accounts.
    """

    password_hash: Optional[str] = None
    user: Any
    active: bool = True
    provisioned: bool = True
    id: Any
    sub: Optional[str] = None


class UserUpdate(BaseModel):
    """Payload for creating or updating a user record.

    Only non-``None`` fields are applied by the storage backend, allowing
    partial updates.

    Attributes
    ----------
    sub : Optional[str]
        SSO subject identifier.
    id : Optional[Any]
        Internal unique identifier.
    email : Optional[str]
        User email address.
    username : Optional[str]
        Display username.
    full_name : Optional[str]
        Full display name.
    roles : Optional[list[Any]]
        Roles to assign to the user.
    """

    sub: Optional[str] = None
    id: Optional[Any] = None
    email: Optional[str] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    roles: Optional[list[Any]] = None
