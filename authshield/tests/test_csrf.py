"""Unit tests for the CSRF protection middleware (Double-Submit Cookie pattern)."""

import asyncio
import hmac
from typing import Any, Dict, List, Optional

import pytest
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from authshield.config import CsrfConfig
from authshield.csrf._csrf_handler import CSRFMiddleware


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _MinimalApp:
    """A trivial object that satisfies scope["app"].exception_handlers."""

    exception_handlers: dict = {}


def _build_scope(
    method: str = "GET",
    path: str = "/",
    headers: Optional[List[tuple]] = None,
    scheme: str = "http",
    server: tuple = ("testserver", 80),
) -> Scope:
    """Construct a minimal ASGI http scope dict for testing."""
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers or [],
        "scheme": scheme,
        "server": server,
        "app": _MinimalApp(),
        "query_string": b"",
        "root_path": "",
        "client": ("127.0.0.1", 12345),
    }


def _run_middleware(
    middleware: CSRFMiddleware,
    scope: Scope,
) -> Dict[str, Any]:
    """Run the CSRF middleware and capture every ASGI message sent.

    Returns a dict with:
        status: integer status code
        headers: list of (name, value) tuples from the response start
        body: concatenated response body bytes
    """
    messages: List[Message] = []

    async def _send(message: Message) -> None:
        messages.append(message)

    async def _receive() -> Message:
        return {"type": "http.disconnect"}

    async def _run() -> None:
        await middleware(scope, _receive, _send)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_run())
    finally:
        loop.close()

    result: Dict[str, Any] = {
        "headers": [],
        "status": None,
        "body": b"",
    }

    for msg in messages:
        if msg["type"] == "http.response.start":
            result["status"] = msg["status"]
            result["headers"] = [
                (k.decode(), v.decode()) for k, v in msg["headers"]
            ]
        elif msg["type"] == "http.response.body":
            result["body"] += msg.get("body", b"")

    return result


def _make_app(
    csrf_config: Optional[CsrfConfig] = None,
    response_body: bytes = b"ok",
    response_status: int = 200,
) -> CSRFMiddleware:
    """Return a CSRF-wrapped ASGI app that echoes back a fixed response."""

    async def _app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": response_status,
                "headers": [],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": response_body,
            }
        )

    config = csrf_config or CsrfConfig()
    return CSRFMiddleware(_app, config)


# ---------------------------------------------------------------------------
# Safe-method pass-through
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "TRACE"])
def test_safe_methods_pass_through(method: str) -> None:
    app = _make_app()
    scope = _build_scope(method=method)
    result = _run_middleware(app, scope)

    assert result["status"] == 200
    assert result["body"] == b"ok"


# ---------------------------------------------------------------------------
# Unsafe methods without tokens are blocked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_unsafe_methods_blocked_when_tokens_missing(method: str) -> None:
    app = _make_app()
    scope = _build_scope(method=method, path="/submit")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    assert result["status"] == 403
    assert b"CSRF" in result["body"]


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


def test_token_match_allows_request() -> None:
    token = "matching-token-value"

    app = _make_app()
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"csrf_token={token}".encode()),
        (b"x-authshield-csrf-token", token.encode()),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 200
    assert result["body"] == b"ok"


def test_token_mismatch_blocks_request() -> None:
    app = _make_app()
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", b"csrf_token=token-aaaa"),
        (b"x-authshield-csrf-token", b"token-bbbb"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_only_cookie_present_is_blocked() -> None:
    app = _make_app()
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", b"csrf_token=some-token"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_only_header_present_is_blocked() -> None:
    app = _make_app()
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"x-authshield-csrf-token", b"some-token"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


# ---------------------------------------------------------------------------
# Custom token names
# ---------------------------------------------------------------------------


def test_custom_cookie_and_header_names() -> None:
    token = "custom-token-value"

    config = CsrfConfig(cookie_name="my_csrf", header_name="X-MY-CSRF")
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"my_csrf={token}".encode()),
        (b"x-my-csrf", token.encode()),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


# ---------------------------------------------------------------------------
# Origin / Referer validation
# ---------------------------------------------------------------------------


def test_origin_mismatch_is_blocked() -> None:
    config = CsrfConfig(trusted_origins=["good.test"])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"good.test"),
        (b"origin", b"https://evil.test"),
        (b"cookie", b"csrf_token=tok"),
        (b"x-authshield-csrf-token", b"tok"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_referer_mismatch_is_blocked() -> None:
    config = CsrfConfig(trusted_origins=["good.test"])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"good.test"),
        (b"referer", b"https://evil.test/page"),
        (b"cookie", b"csrf_token=tok"),
        (b"x-authshield-csrf-token", b"tok"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_trusted_origin_allows_request() -> None:
    config = CsrfConfig(trusted_origins=["good.test"])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"good.test"),
        (b"origin", b"https://good.test"),
        (b"cookie", b"csrf_token=tok"),
        (b"x-authshield-csrf-token", b"tok"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


def test_host_fallback_when_no_trusted_origins() -> None:
    config = CsrfConfig(trusted_origins=[])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"myhost.test"),
        (b"origin", b"https://myhost.test"),
        (b"cookie", b"csrf_token=tok"),
        (b"x-authshield-csrf-token", b"tok"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


def test_host_fallback_blocks_mismatched_origin() -> None:
    config = CsrfConfig(trusted_origins=[])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"myhost.test"),
        (b"origin", b"https://evil.test"),
        (b"cookie", b"csrf_token=tok"),
        (b"x-authshield-csrf-token", b"tok"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


# ---------------------------------------------------------------------------
# Forwarded host
# ---------------------------------------------------------------------------


def test_x_forwarded_host_takes_precedence() -> None:
    config = CsrfConfig(trusted_origins=[])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"internal.local"),
        (b"x-forwarded-host", b"public.test"),
        (b"origin", b"https://public.test"),
        (b"cookie", b"csrf_token=tok"),
        (b"x-authshield-csrf-token", b"tok"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


def test_x_forwarded_host_first_value_used() -> None:
    config = CsrfConfig(trusted_origins=[])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"internal.local"),
        (b"x-forwarded-host", b"first.proxy, second.proxy"),
        (b"origin", b"https://first.proxy"),
        (b"cookie", b"csrf_token=tok"),
        (b"x-authshield-csrf-token", b"tok"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


# ---------------------------------------------------------------------------
# CSRF cookie injection
# ---------------------------------------------------------------------------


def test_csrf_cookie_is_set_on_response() -> None:
    app = _make_app()
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie_values = [
        v for k, v in result["headers"] if k.lower() == "set-cookie"
    ]
    assert len(cookie_values) >= 1
    assert "csrf_token=" in cookie_values[0]


def test_csrf_cookie_preserves_existing_token() -> None:
    existing_token = "preserved-token-value-12345"

    app = _make_app()
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"csrf_token={existing_token}".encode()),
    ]

    result = _run_middleware(app, scope)

    cookie_values = [
        v for k, v in result["headers"] if k.lower() == "set-cookie"
    ]
    assert any(existing_token in line for line in cookie_values)


def test_csrf_cookie_generates_new_token_when_missing() -> None:
    app = _make_app()
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie_values = [
        v for k, v in result["headers"] if k.lower() == "set-cookie"
    ]
    assert len(cookie_values) >= 1
    token_val = cookie_values[0].split(";")[0].split("=", 1)[1]
    assert len(token_val) > 0


# ---------------------------------------------------------------------------
# Cookie attribute configuration
# ---------------------------------------------------------------------------


def test_cookie_path_config() -> None:
    config = CsrfConfig(cookie_path="/app")
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/app")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "Path=/app" in cookie


def test_cookie_samesite_lax_default() -> None:
    app = _make_app()
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "SameSite=Lax" in cookie


def test_cookie_samesite_strict() -> None:
    config = CsrfConfig(cookie_samesite="Strict")
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "SameSite=Strict" in cookie


def test_cookie_samesite_none() -> None:
    config = CsrfConfig(cookie_samesite="None")
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "SameSite=None" in cookie


def test_cookie_max_age_config() -> None:
    config = CsrfConfig(cookie_max_age=3600)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "Max-Age=3600" in cookie


def test_cookie_domain_config() -> None:
    config = CsrfConfig(cookie_domain=".example.com")
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "Domain=.example.com" in cookie


def test_cookie_domain_omitted_when_none() -> None:
    config = CsrfConfig(cookie_domain=None)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "Domain=" not in cookie


def test_cookie_secure_on_https_scheme() -> None:
    app = _make_app()
    scope = _build_scope(method="GET", path="/", scheme="https")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "; Secure" in cookie


def test_cookie_secure_when_config_enabled() -> None:
    config = CsrfConfig(cookie_secure=True)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/", scheme="http")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "; Secure" in cookie


def test_cookie_not_secure_when_disabled_on_http() -> None:
    config = CsrfConfig(cookie_secure=False)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/", scheme="http")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie = [v for k, v in result["headers"] if k.lower() == "set-cookie"][0]
    assert "; Secure" not in cookie


# ---------------------------------------------------------------------------
# Custom safe methods
# ---------------------------------------------------------------------------


def test_custom_safe_methods_are_not_validated() -> None:
    config = CsrfConfig(safe_methods={"GET", "POST"})
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


# ---------------------------------------------------------------------------
# Non-HTTP scopes pass through
# ---------------------------------------------------------------------------


def test_non_http_scope_passes_through() -> None:
    async def _app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = CSRFMiddleware(_app, CsrfConfig())

    scope: Scope = {"type": "websocket", "path": "/ws"}

    messages: List[Message] = []

    async def _send(message: Message) -> None:
        messages.append(message)

    async def _receive() -> Message:
        return {"type": "websocket.connect"}

    async def _run() -> None:
        await middleware(scope, _receive, _send)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_run())
    finally:
        loop.close()

    statuses = [m["status"] for m in messages if m["type"] == "http.response.start"]
    assert 200 in statuses


# ---------------------------------------------------------------------------
# Registered exception handler
# ---------------------------------------------------------------------------


def test_error_goes_through_registered_handler() -> None:
    async def _handler_app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"never-reached"})

    starlette_app = Starlette()
    starlette_app.add_exception_handler(
        HTTPException, lambda req, exc: PlainTextResponse("handled-403", 403)
    )

    async def _dispatch(scope: Scope, receive: Receive, send: Send) -> None:
        await starlette_app(scope, receive, send)

    middleware = CSRFMiddleware(_dispatch, CsrfConfig())
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [(b"host", b"testserver")]
    scope["app"] = starlette_app

    result = _run_middleware(middleware, scope)

    assert result["status"] == 403


# ---------------------------------------------------------------------------
# CsrfConfig defaults
# ---------------------------------------------------------------------------


class TestCsrfConfigDefaults:
    def test_default_cookie_name(self) -> None:
        config = CsrfConfig()
        assert config.cookie_name == "csrf_token"

    def test_default_header_name(self) -> None:
        config = CsrfConfig()
        assert config.header_name == "X-AUTHSHIELD-CSRF-TOKEN"

    def test_default_safe_methods(self) -> None:
        config = CsrfConfig()
        assert config.safe_methods == {"GET", "HEAD", "OPTIONS", "TRACE"}

    def test_default_cookie_max_age(self) -> None:
        config = CsrfConfig()
        assert config.cookie_max_age == 604800

    def test_default_cookie_samesite(self) -> None:
        config = CsrfConfig()
        assert config.cookie_samesite == "Lax"

    def test_default_cookie_secure(self) -> None:
        config = CsrfConfig()
        assert config.cookie_secure is True

    def test_default_cookie_path(self) -> None:
        config = CsrfConfig()
        assert config.cookie_path == "/"

    def test_default_trusted_origins_empty(self) -> None:
        config = CsrfConfig()
        assert config.trusted_origins == []

    def test_default_cookie_domain_none(self) -> None:
        config = CsrfConfig()
        assert config.cookie_domain is None

    def test_default_signed_mode_false(self) -> None:
        """``signed_mode`` defaults to ``False``."""
        config = CsrfConfig()
        assert config.signed_mode is False

    def test_default_session_cookie_name(self) -> None:
        """``session_cookie_name`` defaults to ``"session"``."""
        config = CsrfConfig()
        assert config.session_cookie_name == "session"

    def test_default_secret_key_none(self) -> None:
        """``secret_key`` defaults to ``None``."""
        config = CsrfConfig()
        assert config.secret_key is None

    def test_default_excluded_paths_empty(self) -> None:
        """``excluded_paths`` defaults to an empty list."""
        config = CsrfConfig()
        assert config.excluded_paths == []


# ---------------------------------------------------------------------------
# CsrfConfig signed_mode validation
# ---------------------------------------------------------------------------


class TestCsrfConfigSignedModeValidation:
    def test_signed_mode_without_secret_key_raises(self) -> None:
        """``signed_mode=True`` without ``secret_key`` raises ``ValueError``."""
        with pytest.raises(ValueError, match="secret_key must be provided when signed_mode is True"):
            CsrfConfig(signed_mode=True)

    def test_signed_mode_with_secret_key_valid(self) -> None:
        """``signed_mode=True`` with a ``secret_key`` passes validation."""
        config = CsrfConfig(signed_mode=True, secret_key="test-key")
        assert config.signed_mode is True
        assert config.secret_key == "test-key"

    def test_signed_mode_false_without_secret_key_ok(self) -> None:
        """``signed_mode=False`` does not require ``secret_key``."""
        config = CsrfConfig(signed_mode=False)
        assert config.signed_mode is False


# ---------------------------------------------------------------------------
# Signed mode test helpers
# ---------------------------------------------------------------------------


def _make_signed_token(raw_token: str, session_id: str, secret_key: str) -> str:
    """Generate a signed CSRF cookie value: '<raw>.<hmac-sha256-hex>'."""
    signature = hmac.new(
        secret_key.encode("utf-8"),
        f"{session_id}!{raw_token}".encode("utf-8"),
        digestmod="sha256",
    ).hexdigest()
    return f"{raw_token}.{signature}"


def _make_signed_config(secret_key: str = "test-secret", **kwargs) -> CsrfConfig:
    """Return a CsrfConfig with signed_mode enabled."""
    return CsrfConfig(signed_mode=True, secret_key=secret_key, **kwargs)


# ---------------------------------------------------------------------------
# Signed mode — token generation (cookie injection on responses)
# ---------------------------------------------------------------------------


def test_signed_mode_cookie_is_dot_separated() -> None:
    """In signed mode the cookie value must be ``<raw>.<signature>``."""
    config = _make_signed_config()
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", b"session=user-session-id"),
    ]

    result = _run_middleware(app, scope)

    cookie_values = [
        v for k, v in result["headers"] if k.lower() == "set-cookie"
    ]
    assert len(cookie_values) >= 1
    token_val = cookie_values[0].split(";")[0].split("=", 1)[1]
    parts = token_val.split(".")
    assert len(parts) == 2, f"expected token.sig format, got {token_val}"
    assert len(parts[0]) > 0
    assert len(parts[1]) > 0


def test_signed_mode_no_session_cookie_skips_set_cookie() -> None:
    """Without a session cookie no CSRF cookie is emitted."""
    config = _make_signed_config()
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    cookie_values = [
        v for k, v in result["headers"] if k.lower() == "set-cookie"
    ]
    assert len(cookie_values) == 0


def test_signed_mode_stale_token_deleted_when_no_session() -> None:
    """A stale CSRF cookie without a session must be deleted (Max-Age=0)."""
    stale = _make_signed_token("stale-raw", "gone-session", "test-secret")
    config = _make_signed_config()
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"csrf_token={stale}".encode()),
    ]

    result = _run_middleware(app, scope)

    cookie_values = [
        v for k, v in result["headers"] if k.lower() == "set-cookie"
    ]
    assert len(cookie_values) == 1
    assert "Max-Age=0" in cookie_values[0]
    assert "csrf_token=;" in cookie_values[0]


def test_signed_mode_echoes_token_when_session_unchanged() -> None:
    """When session and token are both present, echo the token unchanged."""
    secret = "test-secret"
    session_id = "sess-abc"
    existing = _make_signed_token("existing-raw", session_id, secret)

    config = _make_signed_config(secret_key=secret)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"session={session_id}; csrf_token={existing}".encode()),
    ]

    result = _run_middleware(app, scope)

    cookie_values = [
        v for k, v in result["headers"] if k.lower() == "set-cookie"
    ]
    assert len(cookie_values) >= 1
    assert any(existing in v for v in cookie_values)


# ---------------------------------------------------------------------------
# Signed mode — token verification on unsafe requests
# ---------------------------------------------------------------------------


def test_signed_mode_valid_tokens_pass() -> None:
    """A correctly-signed token bound to the current session passes validation."""
    secret = "test-secret"
    session_id = "sess-abc"
    raw_token = "raw-token-123"
    signed_cookie = _make_signed_token(raw_token, session_id, secret)
    signature = signed_cookie.split(".", 1)[1]

    config = _make_signed_config(secret_key=secret)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"session={session_id}; csrf_token={signed_cookie}".encode()),
        (b"x-authshield-csrf-token", signature.encode()),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


def test_signed_mode_signature_mismatch_blocked() -> None:
    """A wrong signature in the header is rejected."""
    secret = "test-secret"
    session_id = "sess-abc"
    raw_token = "raw-token-123"
    signed_cookie = _make_signed_token(raw_token, session_id, secret)

    config = _make_signed_config(secret_key=secret)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"session={session_id}; csrf_token={signed_cookie}".encode()),
        (b"x-authshield-csrf-token", b"wrong-signature-value"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_signed_mode_missing_session_cookie_blocked() -> None:
    """Signed mode requires the session cookie to be present on unsafe requests."""
    secret = "test-secret"
    session_id = "sess-abc"
    raw_token = "raw-token-123"
    signed_cookie = _make_signed_token(raw_token, session_id, secret)
    signature = signed_cookie.split(".", 1)[1]

    config = _make_signed_config(secret_key=secret)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"csrf_token={signed_cookie}".encode()),
        (b"x-authshield-csrf-token", signature.encode()),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_signed_mode_malformed_cookie_no_dot_blocked() -> None:
    """A signed cookie without a dot separator is malformed and blocked."""
    secret = "test-secret"
    session_id = "sess-abc"

    config = _make_signed_config(secret_key=secret)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"session={session_id}; csrf_token=no_dot_token".encode()),
        (b"x-authshield-csrf-token", b"some-signature"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_signed_mode_token_stolen_across_sessions_blocked() -> None:
    """A CSRF token signed for session A is invalid when used with session B."""
    secret = "test-secret"
    session_a = "sess-aaa"
    session_b = "sess-bbb"
    raw_token = "raw-token-123"

    signed_for_a = _make_signed_token(raw_token, session_a, secret)
    sig_for_a = signed_for_a.split(".", 1)[1]

    config = _make_signed_config(secret_key=secret)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"session={session_b}; csrf_token={signed_for_a}".encode()),
        (b"x-authshield-csrf-token", sig_for_a.encode()),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_signed_mode_only_cookie_present_blocked() -> None:
    """Having only the CSRF cookie without the header token is blocked."""
    secret = "test-secret"
    session_id = "sess-abc"
    raw_token = "raw-token-123"
    signed_cookie = _make_signed_token(raw_token, session_id, secret)

    config = _make_signed_config(secret_key=secret)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"session={session_id}; csrf_token={signed_cookie}".encode()),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_signed_mode_only_header_present_blocked() -> None:
    """Having only the header token without the CSRF cookie is blocked."""
    secret = "test-secret"

    config = _make_signed_config(secret_key=secret)
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", b"session=sess-abc"),
        (b"x-authshield-csrf-token", b"some-signature"),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 403


def test_signed_mode_safe_method_passes_without_session() -> None:
    """Safe methods (GET, etc.) pass even without a session cookie."""
    config = _make_signed_config()
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="GET", path="/")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


def test_signed_mode_custom_session_cookie_name() -> None:
    """A custom ``session_cookie_name`` is respected for lookup and signing."""
    secret = "test-secret"
    session_id = "sess-xyz"
    raw_token = "raw-custom-sess"
    signed_cookie = _make_signed_token(raw_token, session_id, secret)
    signature = signed_cookie.split(".", 1)[1]

    config = CsrfConfig(
        signed_mode=True,
        secret_key=secret,
        session_cookie_name="custom-session",
    )
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [
        (b"host", b"testserver"),
        (b"cookie", f"custom-session={session_id}; csrf_token={signed_cookie}".encode()),
        (b"x-authshield-csrf-token", signature.encode()),
    ]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


# ---------------------------------------------------------------------------
# Excluded paths
# ---------------------------------------------------------------------------


def test_excluded_path_exact_match_skips_csrf() -> None:
    """An exact ``excluded_paths`` match bypasses CSRF validation."""
    config = CsrfConfig(excluded_paths=["/webhook"])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/webhook")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


def test_excluded_path_prefix_wildcard_skips_csrf() -> None:
    """A trailing ``*`` in an excluded path matches all prefixed routes."""
    config = CsrfConfig(excluded_paths=["/api/public/*"])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/api/public/callback")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    assert result["status"] == 200


def test_excluded_path_does_not_affect_other_paths() -> None:
    """Non-excluded paths are still protected even when other paths are excluded."""
    config = CsrfConfig(excluded_paths=["/webhook"])
    app = _make_app(csrf_config=config)
    scope = _build_scope(method="POST", path="/submit")
    scope["headers"] = [(b"host", b"testserver")]

    result = _run_middleware(app, scope)

    assert result["status"] == 403
