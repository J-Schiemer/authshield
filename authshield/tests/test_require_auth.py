"""Unit tests for the require_auth dependency."""

from typing import Optional

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from authshield.auth._require_auth import require_auth
from authshield.auth._use_auth import get_auth_config
from authshield.auth.models import UserSession
from authshield.config import AuthConfig


class _FakeUser:
    def __init__(self, username: str, roles: Optional[list] = None):
        self.username = username
        self.roles = roles


def _make_session(user: _FakeUser) -> UserSession:
    return UserSession(session_token="abc123", user=user, roles=user.roles)


async def _noop_resolver(token: str) -> Optional[UserSession]:
    return None


# ---------------------------------------------------------------------------
# Helpers to build a configured app
# ---------------------------------------------------------------------------


def _override_config(app: FastAPI, config: AuthConfig) -> None:
    app.dependency_overrides[get_auth_config] = lambda: config


def _configure_app(
    *,
    resolver=None,
    cookie_name: str = "session",
) -> FastAPI:
    app = FastAPI()
    config = AuthConfig(
        get_user=lambda e: None,
        session_resolver=resolver or _noop_resolver,
        cookie_name=cookie_name,
    )
    _override_config(app, config)
    return app


# ---------------------------------------------------------------------------
# Missing / invalid session
# ---------------------------------------------------------------------------


def test_missing_session_cookie_returns_401():
    app = _configure_app()

    @app.get("/protected")
    async def protected(user=Depends(require_auth())):
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/protected")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Not authenticated"


def test_missing_auth_config_on_app_state_returns_500():
    """When auth config was never set, get_auth_config raises a server error."""
    app = FastAPI()

    @app.get("/protected")
    async def protected(user=Depends(require_auth())):
        return {"ok": True}

    client = TestClient(app, cookies={"session": "abc"}, raise_server_exceptions=False)
    resp = client.get("/protected")
    assert resp.status_code == 500


def test_session_resolver_not_configured_returns_500():
    app = FastAPI()
    app.dependency_overrides[get_auth_config] = lambda: AuthConfig(
        get_user=lambda e: None,
        session_resolver=None,
    )

    @app.get("/protected")
    async def protected(user=Depends(require_auth())):
        return {"ok": True}

    client = TestClient(app, cookies={"session": "abc"})
    resp = client.get("/protected")
    assert resp.status_code == 500
    assert "session_resolver" in resp.json()["detail"]


def test_invalid_session_returns_401():

    async def resolver(token: str) -> Optional[UserSession]:
        return None

    app = _configure_app(resolver=resolver)

    @app.get("/protected")
    async def protected(user=Depends(require_auth())):
        return {"ok": True}

    client = TestClient(app, cookies={"session": "expired-token"})
    resp = client.get("/protected")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid or expired session"


# ---------------------------------------------------------------------------
# Valid session — no roles
# ---------------------------------------------------------------------------


def test_valid_session_injects_user():

    async def resolver(token: str) -> Optional[UserSession]:
        return _make_session(_FakeUser("alice", ["user"]))

    app = _configure_app(resolver=resolver)

    @app.get("/protected")
    async def protected(user=Depends(require_auth())):
        return {"username": user.user.username, "session_token": user.session_token}

    client = TestClient(app, cookies={"session": "good-token"})
    resp = client.get("/protected")
    assert resp.status_code == 200
    assert resp.json() == {"username": "alice", "session_token": "abc123"}


# ---------------------------------------------------------------------------
# Role checks
# ---------------------------------------------------------------------------


def test_role_allows_user_with_matching_role():

    async def resolver(token: str) -> Optional[UserSession]:
        return _make_session(_FakeUser("bob", ["admin"]))

    app = _configure_app(resolver=resolver)

    @app.get("/admin")
    async def admin(user=Depends(require_auth("admin"))):
        return {"username": user.user.username}

    client = TestClient(app, cookies={"session": "admin-token"})
    resp = client.get("/admin")
    assert resp.status_code == 200
    assert resp.json()["username"] == "bob"


def test_role_allows_user_with_one_of_multiple_roles():

    async def resolver(token: str) -> Optional[UserSession]:
        return _make_session(_FakeUser("bob", ["editor"]))

    app = _configure_app(resolver=resolver)

    @app.get("/content")
    async def content(user=Depends(require_auth("admin", "editor", "moderator"))):
        return {"ok": True}

    client = TestClient(app, cookies={"session": "x"})
    resp = client.get("/content")
    assert resp.status_code == 200


def test_role_blocks_user_without_matching_role():

    async def resolver(token: str) -> Optional[UserSession]:
        return _make_session(_FakeUser("alice", ["user"]))

    app = _configure_app(resolver=resolver)

    @app.get("/admin")
    async def admin(user=Depends(require_auth("admin"))):
        return {"ok": True}

    client = TestClient(app, cookies={"session": "x"})
    resp = client.get("/admin")
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Insufficient permissions"


def test_role_blocks_when_user_roles_is_none():

    async def resolver(token: str) -> Optional[UserSession]:
        return _make_session(_FakeUser("eve", None))

    app = _configure_app(resolver=resolver)

    @app.get("/admin")
    async def admin(user=Depends(require_auth("admin"))):
        return {"ok": True}

    client = TestClient(app, cookies={"session": "x"})
    resp = client.get("/admin")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Custom cookie name
# ---------------------------------------------------------------------------


def test_custom_cookie_name():

    async def resolver(token: str) -> Optional[UserSession]:
        return _make_session(_FakeUser("alice", ["user"]))

    app = _configure_app(resolver=resolver, cookie_name="authsid")

    @app.get("/protected")
    async def protected(user=Depends(require_auth())):
        return {"username": user.user.username}

    client = TestClient(app, cookies={"authsid": "good-token"})
    resp = client.get("/protected")
    assert resp.status_code == 200
    assert resp.json()["username"] == "alice"


def test_custom_cookie_name_missing():

    async def resolver(token: str) -> Optional[UserSession]:
        return _make_session(_FakeUser("alice", ["user"]))

    app = _configure_app(resolver=resolver, cookie_name="authsid")

    @app.get("/protected")
    async def protected(user=Depends(require_auth())):
        return {"ok": True}

    client = TestClient(app)  # no authsid cookie
    resp = client.get("/protected")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Config read from app.state (real get_auth_config path)
# ---------------------------------------------------------------------------


def test_config_read_from_app_state():
    """Verify the dependency reads AuthConfig from request.app.state."""

    async def resolver(token: str) -> Optional[UserSession]:
        return _make_session(_FakeUser("state-user", ["user"]))

    app = FastAPI()
    app.state.authshield_auth_config = AuthConfig(
        get_user=lambda e: None,
        session_resolver=resolver,
    )

    @app.get("/protected")
    async def protected(user=Depends(require_auth())):
        return {"username": user.user.username}

    client = TestClient(app, cookies={"session": "x"})
    resp = client.get("/protected")
    assert resp.status_code == 200
    assert resp.json()["username"] == "state-user"
