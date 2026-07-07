
from fastapi import FastAPI

from authshield.config import CsrfConfig
from authshield.csrf._csrf_handler import CSRFMiddleware


def use_csrf(self: FastAPI, csrf_config: CsrfConfig) -> None:
    """Configures CSRF protection middleware in your FastAPI application.

    Adds the Double-Submit Cookie CSRF middleware to the application's
    middleware stack with the provided configuration.

    Args:
        csrf_config: A validated CsrfConfig instance with custom settings.
    """
    self.add_middleware(CSRFMiddleware, config=csrf_config)