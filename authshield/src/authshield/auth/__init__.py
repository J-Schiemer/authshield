"""Authentication sub-package.

Re-exports the public authentication API: configuration wiring, password and
SSO authentication handlers, the ``require_auth`` FastAPI dependency, and the
data models used throughout the auth layer.
"""

from authshield.auth._use_auth import use_auth
from authshield.auth._auth_deps import get_auth_config
from authshield.auth._auth_handler import authenticate_user, authenticate_user_by_sso
from authshield.auth._require_auth import require_auth
from authshield.auth.models import UserSession, UserEntry, UserUpdate

__all__ = [
    "use_auth",
    "get_auth_config",
    "authenticate_user",
    "authenticate_user_by_sso",
    "require_auth",
    "UserSession",
    "UserEntry",
    "UserUpdate",
]
