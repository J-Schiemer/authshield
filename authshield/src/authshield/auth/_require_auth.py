from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import Depends, HTTPException, Request

from authshield.auth._auth_deps import get_auth_config

if TYPE_CHECKING:
    from authshield.config import AuthConfig


def require_auth(*roles: Any):
    """FastAPI dependency that validates a session and optionally checks roles.

    Reads the session cookie named by ``AuthConfig.cookie_name``, resolves
    it via ``AuthConfig.session_resolver``, and injects the user object.
    When *roles* are supplied the resolved user must possess at least one
    of them (checked against ``user.roles``).

    Usage::

        from authshield.auth import require_auth

        @app.get("/me")
        async def me(user = Depends(require_auth())):
            ...

        @app.get("/admin")
        async def admin(user = Depends(require_auth("admin", "superadmin"))):
            ...
    """

    async def dependency(
        request: Request,
        config=Depends(get_auth_config),
    ) -> Any:
        session_token: str | None = request.cookies.get(config.cookie_name)
        if not session_token:
            raise HTTPException(status_code=401, detail="Not authenticated")

        if config.session_resolver is None:
            raise HTTPException(
                status_code=500,
                detail="session_resolver not configured on AuthConfig",
            )

        user = await config.session_resolver(session_token)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid or expired session")

        if roles:
            user_roles: list = user.roles or []
            if not any(r in user_roles for r in roles):
                raise HTTPException(status_code=403, detail="Insufficient permissions")

        return user

    return dependency
