from typing import Any, Callable, Coroutine, Literal, Set, List, Optional
from pydantic import BaseModel, Field, model_validator

from authshield.auth.models import UserEntry, UserSession, UserUpdate


class CsrfConfig(BaseModel):
    """Configuration schema for CSRF protection middleware.

    Leverages Pydantic for runtime type safety, validation, and default settings.

    All fields are optional with secure defaults appropriate for most deployments.

    Attributes
    ----------
    cookie_name : str
        Name of the cookie used to store the CSRF token. Default ``"csrf_token"``.
    header_name : str
        Name of the HTTP header the client sends the token in.
        Default ``"X-AUTHSHIELD-CSRF-TOKEN"``.
    cookie_max_age : int
        Lifetime of the CSRF cookie in seconds. Default ``604800`` (7 days).
    cookie_samesite : Literal["Lax", "Strict", "None"]
        SameSite attribute for the cookie. Default ``"Lax"``.
    cookie_domain : Optional[str]
        Domain attribute for the cookie. ``None`` omits the attribute (browser
        defaults to current domain).
    cookie_path : str
        Path attribute for the cookie. Default ``"/"``.
    cookie_secure : bool
        Whether to set the ``Secure`` flag. Default ``True``. The flag is
        always set when the request scheme is ``https``.
    trusted_origins : List[str]
        List of hostnames (without scheme or port) that are allowed to make
        state-changing requests. When empty (default) the request's ``Host``
        header is used as the sole allowed origin.
    safe_methods : Set[str]
        HTTP methods exempt from CSRF validation. Default ``{"GET", "HEAD",
        "OPTIONS", "TRACE"}``.
    excluded_paths : List[str]
        Request paths that bypass CSRF validation entirely. A trailing ``*``
        matches all sub-paths (e.g. ``"/api/public/*"``). Default ``[]``.
    signed_mode : bool
        When ``True`` the CSRF token is cryptographically bound to the user's
        session via HMAC-SHA256. Requires ``secret_key``. Default ``False``.
    session_cookie_name : str
        Name of the cookie holding the session identifier used for signed-mode
        token binding. Default ``"session"``.
    secret_key : Optional[str]
        HMAC secret key required when ``signed_mode`` is enabled. Must be a
        high-entropy string kept private to the server. Default ``None``.

    Example
    -------
    .. code-block:: python

        from authshield.config import CsrfConfig

        config = CsrfConfig(
            trusted_origins=["api.example.com", "app.example.com"],
            cookie_samesite="Strict",
        )
    """

    cookie_name: str = "csrf_token"
    header_name: str = "X-AUTHSHIELD-CSRF-TOKEN"
    cookie_max_age: int = 604800
    cookie_samesite: Literal["Lax", "Strict", "None"] = "Lax"
    cookie_domain: Optional[str] = None
    cookie_path: str = "/"
    cookie_secure: bool = True
    trusted_origins: List[str] = Field(default_factory=list)
    safe_methods: Set[str] = {"GET", "HEAD", "OPTIONS", "TRACE"}
 
    excluded_paths: List[str] = Field(default_factory=list)
 
    signed_mode: bool = False
    session_cookie_name: str = "session"
    secret_key: Optional[str] = None

    @model_validator(mode="after")
    def validate_signed_mode_requirements(self) -> CsrfConfig:
        """Ensures a secret key is present when signed_mode is enabled."""
        if self.signed_mode and not self.secret_key:
            raise ValueError("secret_key must be provided when signed_mode is True.")
        return self
    
class SsoConfig(BaseModel):
    """Configuration for Single Sign-On integration.

    Defines how the auth layer communicates with the application's user
    store for SSO-related operations (lookup by subject, provisioning,
    merging).

    Attributes
    ----------
    get_user_by_sub : Callable[[str], Coroutine]
        Async callable that retrieves a :class:`UserEntry` by its SSO
        subject identifier.  Receives the ``sub`` claim and returns the
        user entry or ``None``.
    update_or_create_user : Callable[[UserUpdate], Coroutine]
        Async callable that creates or updates a user record.  Receives a
        :class:`UserUpdate` and returns the persisted :class:`UserEntry`.
    auto_merging_enabled : bool
        When ``True``, an SSO login whose email matches an existing
        password-based account will link the SSO subject to that account.
        Defaults to ``False``.
    auto_provisioning_enabled : bool
        When ``True``, an SSO login with no matching local account will
        automatically create one.  Defaults to ``False``.
    role_mapping : dict[str, Any]
        Maps SSO claim role names to application role names.  Applied
        during provisioning and merging via :func:`_resolve_roles`.
    default_role : Optional[Any]
        Role automatically assigned to every SSO-provisioned or merged
        user, regardless of claim roles.  ``None`` means no default role.
    """

    get_user_by_sub: Callable[[str], Coroutine[None, None, Optional[UserEntry]]]
    update_or_create_user: Callable[[UserUpdate], Coroutine[None, None, UserEntry]]
    auto_merging_enabled: bool = False
    auto_provisioning_enabled: bool = False
    role_mapping: dict[str, Any] = {}
    default_role: Optional[Any] = None

class AuthConfig(BaseModel):
    """Top-level authentication configuration.

    Bundles SSO settings, session resolution, and the user-store
    lookup callable into a single object that is wired into the
    FastAPI application state via :func:`~authshield.auth.use_auth`.

    Attributes
    ----------
    sso_enabled : bool
        Whether SSO authentication is available.  Defaults to ``False``.
    sso_config : Optional[SsoConfig]
        SSO-specific configuration.  Required when ``sso_enabled`` is
        ``True``; otherwise ``None``.
    cookie_name : str
        Name of the cookie that carries the session token.  The
        ``require_auth`` dependency reads this cookie.  Defaults to
        ``"session"``.
    session_resolver : Optional[Callable[[str], Coroutine]]
        Async callable that maps a session token string to a
        :class:`UserSession` (or ``None`` when the token is invalid or
        expired).  Used by :func:`~authshield.auth.require_auth`.
    get_user : Callable[[str], Coroutine]
        Async callable that retrieves a :class:`UserEntry` by email
        address.  Used by the password authentication flow and
        ``authenticate_user_by_sso`` for email-based account matching.
    """

    sso_enabled: bool = False
    sso_config: SsoConfig | None = None
    cookie_name: str = "session"
    session_resolver: Callable[[str], Coroutine[None, None, Optional[UserSession]]] | None = None
    get_user: Callable[[str], Coroutine[None, None, UserEntry]]