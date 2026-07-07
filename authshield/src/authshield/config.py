from typing import Literal, Set, List, Optional
from pydantic import BaseModel, Field


class CsrfConfig(BaseModel):
    """Configuration schema for CSRF protection middleware.

    Leverages Pydantic for runtime type safety, validation, and default settings.

    All fields are optional with secure defaults appropriate for most deployments.

    Attributes
    ----------
    cookie_name : str
        Name of the cookie used to store the CSRF token. Default ``"csrf_token"``.
    header_name : str
        Name of the HTTP header the client sends the token in.
        Default ``"X-AUTHSHIELD-CSRF-TOKEN"``.
    cookie_max_age : int
        Lifetime of the CSRF cookie in seconds. Default ``604800`` (7 days).
    cookie_samesite : Literal["Lax", "Strict", "None"]
        SameSite attribute for the cookie. Default ``"Lax"``.
    cookie_domain : Optional[str]
        Domain attribute for the cookie. ``None`` omits the attribute (browser
        defaults to current domain).
    cookie_path : str
        Path attribute for the cookie. Default ``"/"``.
    cookie_secure : bool
        Whether to set the ``Secure`` flag. Default ``True``. The flag is
        always set when the request scheme is ``https``.
    trusted_origins : List[str]
        List of hostnames (without scheme or port) that are allowed to make
        state-changing requests. When empty (default) the request's ``Host``
        header is used as the sole allowed origin.
    safe_methods : Set[str]
        HTTP methods exempt from CSRF validation. Default ``{"GET", "HEAD",
        "OPTIONS", "TRACE"}``.

    Example
    -------
    .. code-block:: python

        from authshield.config import CsrfConfig

        config = CsrfConfig(
            trusted_origins=["api.example.com", "app.example.com"],
            cookie_samesite="Strict",
        )
    """

    cookie_name: str = "csrf_token"
    header_name: str = "X-AUTHSHIELD-CSRF-TOKEN"
    cookie_max_age: int = 604800
    cookie_samesite: Literal["Lax", "Strict", "None"] = "Lax"
    cookie_domain: Optional[str] = None
    cookie_path: str = "/"
    cookie_secure: bool = True
    trusted_origins: List[str] = Field(default_factory=list)
    safe_methods: Set[str] = {"GET", "HEAD", "OPTIONS", "TRACE"}