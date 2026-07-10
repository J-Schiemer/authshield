"""Unit tests for the authentication route handlers."""

import asyncio
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from starlette.responses import RedirectResponse

from authshield.auth._auth_routes import login, logout, sso_login, sso_redirect
from authshield.auth.models import UserSession
from authshield.config import AuthConfig, AuthEndpointConfig, SsoAuthParams
from authshield.session.base import SessionStorage


def _make_session(
    token: str = "mock-token-abc",
    username: str = "testuser",
    roles: Optional[list] = None,
) -> UserSession:
    """Return a valid :class:`UserSession` with a JSON-serializable user dict."""
    return UserSession(
        session_token=token,
        user={"username": username, "roles": roles},
        roles=roles,
    )


class _MockRateLimiter:
    """Mock rate limiter exposing :class:`AsyncMock` hooks for login tests."""

    def __init__(self, *, blocked: bool = False):
        self.is_blocked = AsyncMock(return_value=blocked)
        self.record_failure = AsyncMock()
        self.reset = AsyncMock()


class _MockSessionStorage(SessionStorage):
    """In-memory session store mock that inherits from :class:`SessionStorage` so
    Pydantic validation passes, while exposing :class:`AsyncMock` hooks for
    assertions."""

    async def create(self, session: UserSession) -> None:
        pass

    async def get(self, session_token: str) -> Optional[UserSession]:
        return None

    async def delete(self, session_token: str) -> None:
        pass

    def __init__(self):
        self.create = AsyncMock()  # type: ignore[assignment]
        self.get = AsyncMock(return_value=None)  # type: ignore[assignment]
        self.delete = AsyncMock()  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers to build configured apps
# ---------------------------------------------------------------------------


class _Missing:
    """Sentinel signalling that a keyword argument was omitted."""

    pass


_MISSING = _Missing()


def _make_auth_config(
    *,
    password_auth_enabled: bool = True,
    get_user: Any = None,
    session_storage: SessionStorage | None = _MISSING,  # type: ignore[assignment]
    session_resolver: Any = None,
    rate_limiter: Any = None,
    sso_auth_params: list | None = None,
    cookie_name: str = "session",
) -> AuthConfig:
    """Build an :class:`AuthConfig` with sensible test defaults and opt-in overrides."""

    endpoint_config = AuthEndpointConfig(
        sso_auth_params=sso_auth_params or [],
    )
    if rate_limiter:
        endpoint_config.rate_limiter = rate_limiter

    kwargs: dict[str, Any] = dict(
        password_auth_enabled=password_auth_enabled,
        auth_endpoint_config=endpoint_config,
        get_user=get_user or AsyncMock(return_value=None),
        session_resolver=session_resolver,
        routes_enabled=True,
        cookie_name=cookie_name,
    )
    if session_storage is not _MISSING:
        kwargs["session_storage"] = session_storage

    return AuthConfig(**kwargs)


def _make_sso_provider(name: str = "test-provider") -> SsoAuthParams:
    """Return a minimal :class:`SsoAuthParams` for SSO route tests."""
    return SsoAuthParams(
        name=name,
        oidc_issuer="https://idp.example.com",
        oidc_client_id="client-id",
        oidc_client_secret="client-secret",
        oidc_redirect_uri="https://app.example.com/callback",
        browser_success_redirect="/dashboard",
        browser_failure_redirect="/login",
    )


def _make_oauth_mock(
    provider_name: str = "test-provider",
    *,
    authorize_redirect_url: str = "https://idp.example.com/authorize?state=xyz",
    authorize_access_token_return: Any = None,
    userinfo_return: Any = None,
) -> MagicMock:
    """Build a mock OAuth object whose named provider returns a real
    :class:`~starlette.responses.RedirectResponse` from ``authorize_redirect``
    and async mocks for token / userinfo exchange."""

    redirect_response = RedirectResponse(url=authorize_redirect_url)
    provider_mock = MagicMock()
    provider_mock.authorize_redirect = AsyncMock(return_value=redirect_response)
    provider_mock.authorize_access_token = AsyncMock(
        return_value=authorize_access_token_return or {"access_token": "mock"}
    )
    provider_mock.userinfo = AsyncMock(return_value=userinfo_return)
    oauth_mock = MagicMock()
    setattr(oauth_mock, provider_name, provider_mock)
    return oauth_mock


def _make_app_with_routes(
    *,
    config: AuthConfig | None = None,
    oauth: MagicMock | None = None,
) -> FastAPI:
    """Create a FastAPI app with auth routes registered and state configured."""
    app = FastAPI()
    app.state.authshield_auth_config = config or _make_auth_config()
    if oauth:
        app.state.authshield_oauth = oauth
    app.add_api_route("/login", login, methods=["POST"])
    app.add_api_route("/logout", logout, methods=["POST"])
    app.add_api_route("/sso/flow/{name}", sso_redirect)
    app.add_api_route("/sso/flow/{name}/result", sso_login)
    return app


# ---------------------------------------------------------------------------
# Login route
# ---------------------------------------------------------------------------


class TestLogin:
    """Tests for the ``POST /login`` route handler."""

    def test_successful_login_returns_user_and_sets_cookie(self):
        """A valid email/password pair returns the user object and sets the session cookie."""
        session = _make_session(token="good-token", username="alice")
        rl = _MockRateLimiter()
        config = _make_auth_config(rate_limiter=rl)
        app = _make_app_with_routes(config=config)

        with patch(
            "authshield.auth._auth_routes.authenticate_user", return_value=session
        ):
            client = TestClient(app)
            resp = client.post(
                "/login", json={"email": "alice@example.com", "password": "secret"}
            )

        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"
        set_cookie = resp.headers.get("set-cookie", "")
        assert "good-token" in set_cookie
        assert "HttpOnly" in set_cookie

    def test_disabled_password_auth_returns_403(self):
        """When password_auth_enabled is False the route rejects with 403."""
        config = _make_auth_config(password_auth_enabled=False)
        app = _make_app_with_routes(config=config)

        client = TestClient(app)
        resp = client.post(
            "/login", json={"email": "u@example.com", "password": "pw"}
        )

        assert resp.status_code == 403
        assert "disabled" in resp.json()["detail"].lower()

    def test_rate_limited_by_email_returns_429(self):
        """Requests blocked by the email-key rate limiter receive a 429 response."""
        rl = _MockRateLimiter(blocked=True)
        config = _make_auth_config(rate_limiter=rl)
        app = _make_app_with_routes(config=config)

        client = TestClient(app)
        resp = client.post(
            "/login", json={"email": "blocked@example.com", "password": "pw"}
        )

        assert resp.status_code == 429

    def test_rate_limited_by_ip_returns_429(self):
        """Requests blocked by the IP-key rate limiter receive a 429 response."""
        rl = _MockRateLimiter(blocked=True)
        config = _make_auth_config(rate_limiter=rl)
        app = _make_app_with_routes(config=config)

        client = TestClient(app)
        resp = client.post(
            "/login", json={"email": "someone@example.com", "password": "pw"}
        )

        assert resp.status_code == 429

    def test_invalid_credentials_returns_401_and_records_failure(self):
        """When authenticate_user returns None the route returns 401 and records rate-limiter failures."""
        rl = _MockRateLimiter()
        config = _make_auth_config(rate_limiter=rl)
        app = _make_app_with_routes(config=config)

        with patch(
            "authshield.auth._auth_routes.authenticate_user", return_value=None
        ):
            client = TestClient(app)
            resp = client.post(
                "/login", json={"email": "u@example.com", "password": "wrong"}
            )

        assert resp.status_code == 401
        assert "invalid" in resp.json()["detail"].lower()
        rl.record_failure.assert_any_call("login:email:u@example.com")
        rl.record_failure.assert_any_call("login:ip:testclient")

    def test_rate_limiter_reset_on_successful_login(self):
        """A successful login resets both the email and IP rate-limiter keys."""
        session = _make_session()
        rl = _MockRateLimiter()
        config = _make_auth_config(rate_limiter=rl)
        app = _make_app_with_routes(config=config)

        with patch(
            "authshield.auth._auth_routes.authenticate_user", return_value=session
        ):
            client = TestClient(app)
            resp = client.post(
                "/login", json={"email": "good@example.com", "password": "pw"}
            )

        assert resp.status_code == 200
        rl.reset.assert_any_call("login:email:good@example.com")
        rl.reset.assert_any_call("login:ip:testclient")

    def test_session_storage_create_called_on_success(self):
        """When session_storage is configured, create() is awaited with the auth result."""
        session = _make_session()
        storage = _MockSessionStorage()
        rl = _MockRateLimiter()
        config = _make_auth_config(session_storage=storage, rate_limiter=rl)
        app = _make_app_with_routes(config=config)

        with patch(
            "authshield.auth._auth_routes.authenticate_user", return_value=session
        ):
            client = TestClient(app)
            client.post("/login", json={"email": "a@example.com", "password": "pw"})

        storage.create.assert_awaited_once_with(session)


# ---------------------------------------------------------------------------
# Logout route
# ---------------------------------------------------------------------------


class TestLogout:
    """Tests for the ``POST /logout`` route handler."""

    def test_logout_deletes_session_and_cookie(self):
        """A valid session results in the session being deleted from storage and the cookie cleared."""
        session = _make_session(token="revoke-me")
        storage = _MockSessionStorage()

        async def _resolver(token: str) -> Optional[UserSession]:
            return session if token == "revoke-me" else None

        config = _make_auth_config(
            session_storage=storage,
            session_resolver=_resolver,
        )
        app = _make_app_with_routes(config=config)

        client = TestClient(app, cookies={"session": "revoke-me"})
        resp = client.post("/logout")

        assert resp.status_code == 200
        assert resp.json()["message"] == "Logged out successfully"
        storage.delete.assert_awaited_once_with("revoke-me")

        set_cookie = resp.headers.get("set-cookie", "")
        assert 'session="";' in set_cookie or "session=;" in set_cookie

    def test_logout_without_storage_still_clears_cookie(self):
        """Even without session_storage the cookie is deleted and 200 returned."""
        session = _make_session(token="token-x")

        async def _resolver(token: str) -> Optional[UserSession]:
            return session if token == "token-x" else None

        config = _make_auth_config(session_resolver=_resolver, session_storage=None)
        app = _make_app_with_routes(config=config)

        client = TestClient(app, cookies={"session": "token-x"})
        resp = client.post("/logout")

        assert resp.status_code == 200
        assert resp.json()["message"] == "Logged out successfully"

        set_cookie = resp.headers.get("set-cookie", "")
        assert 'session="";' in set_cookie or "session=;" in set_cookie

    def test_logout_with_no_cookie_still_clears_cookie(self):
        """delete_cookie is called even when no session token is present in the request."""

        async def _run():
            config = _make_auth_config()
            scope: dict[str, Any] = {"type": "http", "headers": [], "app": FastAPI()}
            scope["app"].state.authshield_auth_config = config
            request = Request(scope)
            response = Response()
            result = await logout(
                request, response, _user=_make_session()
            )
            return result, response

        result, response = asyncio.run(_run())

        assert result == {"message": "Logged out successfully"}
        set_cookie = response.headers.get("set-cookie", "")
        assert 'session="";' in set_cookie or "session=;" in set_cookie


# ---------------------------------------------------------------------------
# SSO redirect route
# ---------------------------------------------------------------------------


class TestSsoRedirect:
    """Tests for the ``GET /sso/flow/{name}`` route handler."""

    def test_missing_provider_returns_404(self):
        """A provider name not in sso_auth_params results in a 404."""
        config = _make_auth_config()
        oauth = _make_oauth_mock()
        app = _make_app_with_routes(config=config, oauth=oauth)

        client = TestClient(app)
        resp = client.get("/sso/flow/unknown-provider")

        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_valid_provider_redirects_to_idp(self):
        """A known provider triggers an OAuth redirect to the identity provider."""
        provider = _make_sso_provider(name="myidp")
        config = _make_auth_config(sso_auth_params=[provider])
        oauth = _make_oauth_mock(
            provider_name="myidp",
            authorize_redirect_url="https://idp.example.com/authorize?state=xyz",
        )
        app = _make_app_with_routes(config=config, oauth=oauth)

        client = TestClient(app)
        resp = client.get("/sso/flow/myidp", follow_redirects=False)

        assert resp.status_code == 307
        assert resp.headers["location"] == "https://idp.example.com/authorize?state=xyz"

    def test_provider_overrides_browser_url(self):
        """When oidc_browser_url is set the redirect location is rewritten to use the override."""
        provider = _make_sso_provider(name="myidp")
        provider.oidc_browser_url = "https://proxy.example.com/auth"
        config = _make_auth_config(sso_auth_params=[provider])
        oauth = _make_oauth_mock(
            provider_name="myidp",
            authorize_redirect_url="https://idp.example.com/authorize?state=xyz",
        )
        app = _make_app_with_routes(config=config, oauth=oauth)

        client = TestClient(app)
        resp = client.get("/sso/flow/myidp", follow_redirects=False)

        assert resp.status_code == 307
        assert resp.headers["location"].startswith(
            "https://proxy.example.com/auth/authorize"
        )


# ---------------------------------------------------------------------------
# SSO login (callback) route
# ---------------------------------------------------------------------------


class TestSsoLogin:
    """Tests for the ``GET /sso/flow/{name}/result`` route handler."""

    def test_missing_provider_returns_404(self):
        """A provider name not in sso_auth_params results in a 404."""
        config = _make_auth_config()
        oauth = _make_oauth_mock()
        app = _make_app_with_routes(config=config, oauth=oauth)

        client = TestClient(app)
        resp = client.get("/sso/flow/unknown-provider/result", follow_redirects=False)

        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_missing_userinfo_redirects_to_failure_url(self):
        """When userinfo returns a falsy value the client is redirected to the failure URL."""
        provider = _make_sso_provider(name="myidp")
        config = _make_auth_config(sso_auth_params=[provider])
        oauth = _make_oauth_mock(provider_name="myidp", userinfo_return=None)
        app = _make_app_with_routes(config=config, oauth=oauth)

        with patch(
            "authshield.auth._auth_routes.authenticate_user_by_sso"
        ) as mock_sso:
            client = TestClient(app)
            resp = client.get(
                "/sso/flow/myidp/result", follow_redirects=False
            )

        assert resp.status_code == 307
        assert resp.headers["location"] == "/login?error=missing_userinfo"
        mock_sso.assert_not_called()

    def test_authentication_failed_redirects_to_failure_url(self):
        """When authenticate_user_by_sso returns None the client is redirected to the failure URL."""
        provider = _make_sso_provider(name="myidp")
        config = _make_auth_config(sso_auth_params=[provider])
        oauth = _make_oauth_mock(
            provider_name="myidp",
            userinfo_return={"sub": "user1", "email": "u@example.com"},
        )
        app = _make_app_with_routes(config=config, oauth=oauth)

        with patch(
            "authshield.auth._auth_routes.authenticate_user_by_sso",
            return_value=None,
        ):
            client = TestClient(app)
            resp = client.get(
                "/sso/flow/myidp/result", follow_redirects=False
            )

        assert resp.status_code == 307
        assert resp.headers["location"] == "/login?error=authentication_failed"

    def test_successful_sso_sets_cookie_and_redirects_to_success_url(self):
        """A successful SSO login sets the session cookie and redirects to the success URL."""
        session = _make_session(token="sso-token", username="sso-user")
        provider = _make_sso_provider(name="myidp")
        config = _make_auth_config(sso_auth_params=[provider])
        oauth = _make_oauth_mock(
            provider_name="myidp",
            userinfo_return={"sub": "user1", "email": "u@example.com"},
        )
        app = _make_app_with_routes(config=config, oauth=oauth)

        with patch(
            "authshield.auth._auth_routes.authenticate_user_by_sso",
            return_value=session,
        ):
            client = TestClient(app)
            resp = client.get(
                "/sso/flow/myidp/result", follow_redirects=False
            )

        assert resp.status_code == 307
        assert resp.headers["location"] == "/dashboard"
        set_cookie = resp.headers.get("set-cookie", "")
        assert "sso-token" in set_cookie
        assert "HttpOnly" in set_cookie

    def test_exception_during_sso_redirects_to_failure_url(self):
        """An unexpected exception during SSO processing redirects to the failure URL."""
        provider = _make_sso_provider(name="myidp")
        config = _make_auth_config(sso_auth_params=[provider])
        oauth = _make_oauth_mock(provider_name="myidp")
        oauth_provider = getattr(oauth, "myidp")
        oauth_provider.authorize_access_token.side_effect = RuntimeError("boom")

        app = _make_app_with_routes(config=config, oauth=oauth)

        client = TestClient(app)
        resp = client.get("/sso/flow/myidp/result", follow_redirects=False)

        assert resp.status_code == 307
        assert resp.headers["location"] == "/login?error=sso_failed"
