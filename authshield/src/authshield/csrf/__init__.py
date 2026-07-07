"""Cross-Site Request Forgery (CSRF) protection for FastAPI / Starlette applications.

Implements the `Double-Submit Cookie pattern
<https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie>`_
— a stateless anti-CSRF mechanism that requires no server-side session storage.

Public API
----------
- :class:`~authshield.csrf.CSRFMiddleware` — ASGI middleware that validates tokens.
- :func:`~authshield.csrf.use_csrf` — Convenience helper that registers the
  middleware on a FastAPI application.
"""

from authshield.csrf._csrf_handler import CSRFMiddleware
from authshield.csrf._use_csrf import use_csrf

__all__ = ["CSRFMiddleware", "use_csrf"]
