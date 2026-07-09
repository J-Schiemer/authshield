"""authshield -- modular security suite for FastAPI applications.

Provides authentication (password + SSO), CSRF protection, and session
management through a dynamic factory architecture that injects chainable
configuration methods into your application class at runtime.
"""

from authshield.extended import shield_class
from authshield.csrf import CSRFMiddleware, use_csrf
from authshield.config import CsrfConfig, AuthConfig, SsoConfig
from authshield.auth import use_auth, get_auth_config, authenticate_user, authenticate_user_by_sso, require_auth, UserSession, UserEntry, UserUpdate

__all__ = [
    "shield_class",
    "CSRFMiddleware",
    "use_csrf",
    "CsrfConfig",
    "AuthConfig",
    "SsoConfig",
    "use_auth",
    "get_auth_config",
    "authenticate_user",
    "authenticate_user_by_sso",
    "require_auth",
    "UserSession",
    "UserEntry",
    "UserUpdate",
]

__version__ = "0.1.0"