from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, Request

if TYPE_CHECKING:
    from authshield.config import AuthConfig


def use_auth(self: FastAPI, auth_config: AuthConfig) -> None:
    """Register authentication configuration on the FastAPI application.

    Stores the ``AuthConfig`` on ``app.state`` so that route dependencies
    and middlewares can retrieve it via ``Request.app.state``.

    Args:
        auth_config: A validated :class:`~authshield.config.AuthConfig` instance
            that defines user lookup callbacks and SSO settings.
    """
    self.state.authshield_auth_config = auth_config


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
