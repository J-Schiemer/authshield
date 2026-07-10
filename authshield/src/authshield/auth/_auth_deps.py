from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request

if TYPE_CHECKING:
    from authshield.config import AuthConfig


def get_auth_config(request: Request) -> AuthConfig:
    """FastAPI dependency that retrieves the AuthConfig from application state.

    Usage::

        from fastapi import Depends
        from authshield.auth import get_auth_config

        @app.get("/users/me")
        async def me(config: AuthConfig = Depends(get_auth_config)):
            ...
    """
    return request.app.state.authshield_auth_config
