from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from fastapi import FastAPI
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware

from authshield.auth._auth_routes import login, logout, sso_login, sso_redirect

if TYPE_CHECKING:
    from authshield.config import AuthConfig


def use_auth(self: FastAPI, auth_config: AuthConfig) -> None:
    """Register authentication configuration on the FastAPI application.

    Stores the ``AuthConfig`` on ``app.state`` so that route dependencies
    and middlewares can retrieve it via ``Request.app.state``.

    When ``auth_config.session_storage`` is set and
    ``auth_config.session_resolver`` is ``None``, a resolver backed by
    the storage is created automatically so that ``require_auth`` works
    out of the box.

    Args:
        auth_config: A validated :class:`~authshield.config.AuthConfig` instance
            that defines user lookup callbacks and SSO settings.
    """
    if auth_config.session_storage is not None and auth_config.session_resolver is None:
        storage = auth_config.session_storage
        auth_config.session_resolver = storage.get
        
    if auth_config.routes_enabled:
        if auth_config.sso_enabled and auth_config.auth_endpoint_config.sso_auth_params:
            self.state.authshield_oauth = OAuth()

            secret = auth_config.sso_session_secret_key or secrets.token_urlsafe(32)
            self.add_middleware(SessionMiddleware, secret_key=secret)

            for auth_params in auth_config.auth_endpoint_config.sso_auth_params:
                self.state.authshield_oauth.register(
                    name=auth_params.name,
                    client_id=auth_params.oidc_client_id,
                    client_secret=auth_params.oidc_client_secret,
                    server_metadata_url=f"{auth_params.oidc_issuer}/.well-known/openid-configuration",
                    client_kwargs={"scope": " ".join(auth_params.oidc_scopes)},
                )

            prefix = auth_config.auth_endpoint_config.path_prefix
            self.add_api_route(f"{prefix}/sso/flow/{{name}}", sso_redirect)
            self.add_api_route(f"{prefix}/sso/flow/{{name}}/result", sso_login)
        
        self.add_api_route(f"{auth_config.auth_endpoint_config.path_prefix}/login", login, methods=["POST"])
        self.add_api_route(f"{auth_config.auth_endpoint_config.path_prefix}/logout", logout, methods=["POST"])

    self.state.authshield_auth_config = auth_config
