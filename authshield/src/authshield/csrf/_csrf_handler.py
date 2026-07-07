"""Stateless ASGI middleware implementing the Double-Submit Cookie CSRF pattern.

This module provides :class:`CSRFMiddleware`, an ASGI-compliant middleware that
protects against Cross-Site Request Forgery attacks by requiring state-changing
HTTP requests to carry a cryptographically-random token in both a cookie and an
HTTP header.

Architecture
----------
1. **Token delivery** — Every response sets a ``csrf_token`` cookie with a
   freshly-generated or preserved secret token.
2. **Token verification** — Non-safe methods (POST, PUT, DELETE, PATCH) must
   present the same token value in both the cookie and the
   ``X-AUTHSHIELD-CSRF-TOKEN`` header.
3. **Origin validation** — The middleware checks the ``Origin`` and ``Referer``
   headers against a configured set of trusted origins, falling back to the
   ``Host`` header when no explicit origins are provided.
4. **Error routing** — On CSRF failure a ``403 Forbidden`` is raised via the
   application's registered :class:`~starlette.exceptions.HTTPException` handler,
   or emitted directly as a plain-text body if no handler is registered.

Usage
-----
.. code-block:: python

    from authshield.config import CsrfConfig
    from authshield.csrf import CSRFMiddleware

    config = CsrfConfig(trusted_origins=["example.com"])
    app.add_middleware(CSRFMiddleware, config=config)

Or via the shortcut helper:

.. code-block:: python

    from authshield import use_csrf, CsrfConfig

    shielded_app.use_csrf(CsrfConfig())

References
----------
- `OWASP Double-Submit Cookie Pattern <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie>`_
"""

import asyncio
import html
import hmac
import logging
import secrets
from urllib.parse import urlparse

from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from authshield.config import CsrfConfig


class CSRFMiddleware:
    """Stateless ASGI middleware providing Cross-Site Request Forgery (CSRF) protection.

    Utilizes the Double-Submit Cookie pattern, validating that a secure token
    delivered via an HTTP cookie matches a corresponding custom payload header.

    The middleware is stateless — no server-side token storage is required.
    It operates by comparing the value of a randomly-generated cookie against
    a custom HTTP header submitted by the client.

    Parameters
    ----------
    app : ASGIApp
        The downstream ASGI application to wrap.
    config : CsrfConfig
        A validated Pydantic :class:`~authshield.config.CsrfConfig` instance
        controlling cookie name, header name, trusted origins, and other
        security parameters.
    """

    def __init__(self, app: ASGIApp, config: CsrfConfig):
        """Initializes the CSRF middleware.

        Args:
            app: The downstream ASGI application.
            config: A validated Pydantic CsrfConfig instance.
        """
        self.app = app
        self.config = config
        self.logger = logging.getLogger(__name__)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point. Intercepts HTTP requests and validates CSRF tokens."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        if request.method not in self.config.safe_methods:
            error_msg = self._validate_origins(request) or self._validate_tokens(
                request
            )
            if error_msg:
                self.logger.warning(
                    f"CSRF Blocked: {error_msg} | Path: {request.url.path} | Method: {request.method}"
                )
                await self._trigger_error(scope, receive, send)
                return

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                self._ensure_csrf_cookie(scope, message, request)
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _get_effective_host(self, headers: Headers) -> str:
        """Extracts the definitive network location, respecting reverse proxies.

        If the ``X-Forwarded-Host`` header is present, its first value
        (comma-separated) is used. Otherwise falls back to the ``Host`` header.

        Parameters
        ----------
        headers : Headers
            The Starlette request headers.

        Returns
        -------
        str
            The effective hostname (lowercase, stripped).
        """
        forwarded_host = headers.get("x-forwarded-host")
        if forwarded_host:
            return forwarded_host.split(",")[0].strip()
        return headers.get("host", "").strip()

    def _validate_origins(self, request: Request) -> str | None:
        """Validates incoming Origin and Referer headers against trusted endpoints.

        When ``trusted_origins`` is configured the origin/referer netloc must
        appear in that list. When empty the ``Host`` header (or
        ``X-Forwarded-Host``) is used as the sole allowed origin.

        Parameters
        ----------
        request : Request
            The incoming Starlette request.

        Returns
        -------
        str | None
            An error description string if a mismatch is detected, or ``None``
            when both headers are valid (or absent).
        """
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")

        allowed = (
            set(self.config.trusted_origins)
            if self.config.trusted_origins
            else {self._get_effective_host(request.headers)}
        )

        for source, name in [(origin, "origin"), (referer, "referer")]:
            if source:
                netloc = urlparse(source).netloc
                if netloc not in allowed:
                    escaped = html.escape(netloc)
                    return f"CSRF {name} mismatch: browser sent '{escaped}', allowed targets: {allowed}"
        return None

    def _validate_tokens(self, request: Request) -> str | None:
        """Validates cookie value against custom header using constant-time comparison.

        Both the cookie and header tokens must be present and match exactly.

        Parameters
        ----------
        request : Request
            The incoming Starlette request.

        Returns
        -------
        str | None
            An error description if validation fails, or ``None`` on success.
        """
        cookie_token = request.cookies.get(self.config.cookie_name)
        header_token = request.headers.get(self.config.header_name)

        if not cookie_token or not header_token:
            return f"CSRF token missing (Cookie: {bool(cookie_token)}, Header: {bool(header_token)})"

        if not hmac.compare_digest(cookie_token, header_token):
            return "CSRF token mismatch between client header and client cookie"

        return None

    def _ensure_csrf_cookie(self, scope: Scope, message: dict, request: Request) -> None:
        """Injects or maintains the client-side CSRF token cookie in the response.

        If the request already carries a CSRF cookie its value is echoed back
        unchanged to avoid race conditions from concurrent requests. Otherwise
        a fresh 32-byte URL-safe token is generated via :func:`secrets.token_urlsafe`.

        Parameters
        ----------
        scope : Scope
            The ASGI scope dict, used to detect the scheme (http/https).
        message : dict
            The ``http.response.start`` message whose headers will be mutated.
        request : Request
            The incoming request, read for the existing CSRF cookie value.
        """
        res_headers = MutableHeaders(scope=message)

        token = request.cookies.get(self.config.cookie_name)
        if not token:
            token = secrets.token_urlsafe(32)

        cookie_str = (
            f"{self.config.cookie_name}={token}; "
            f"Path={self.config.cookie_path}; "
            f"Max-Age={self.config.cookie_max_age}; "
            f"SameSite={self.config.cookie_samesite}"
        )
        
        if self.config.cookie_domain:
            cookie_str += f"; Domain={self.config.cookie_domain}"

        if scope.get("scheme") == "https" or self.config.cookie_secure:
            cookie_str += "; Secure"

        res_headers.append("Set-Cookie", cookie_str)

    async def _trigger_error(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Routes CSRF failures through the application's exception-handling machinery.

        Looks up the root application on ``scope["app"]`` and attempts to use
        its registered :class:`~starlette.exceptions.HTTPException` handler.
        Falls back to a plain 403 text response if no handler is registered.

        Parameters
        ----------
        scope : Scope
            The ASGI scope dict, which must carry the root application at
            ``scope["app"]``.
        receive : Receive
            The ASGI receive callable.
        send : Send
            The ASGI send callable.
        """
        exc = HTTPException(
            status_code=403, detail="CSRF Error: See App Logs for Details."
        )
        app = scope["app"]

        handler = app.exception_handlers.get(
            HTTPException
        ) or app.exception_handlers.get(Exception)
        if handler:
            request = Request(scope, receive)
            result = handler(request, exc)
            response = await result if asyncio.iscoroutine(result) else result
            await response(scope, receive, send)
            return

        await Response(
            "CSRF Error: Access Denied", status_code=403
        )(scope, receive, send)