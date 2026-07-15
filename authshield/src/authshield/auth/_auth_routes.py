from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from authshield._shared.rate_limiter import RateLimiter
from authshield.auth._auth_handler import authenticate_user, authenticate_user_by_sso
from authshield.auth._require_auth import require_auth
from authshield.auth.endpoint_models import LoginRequest

if TYPE_CHECKING:
    from authshield.config import AuthConfig


async def login(login_model: LoginRequest, request: Request, response: Response) -> Any:
    app: FastAPI = request.app
    settings: AuthConfig = app.state.authshield_auth_config

    if not settings.password_auth_enabled:
        raise HTTPException(
            status_code=403, detail="Username/Password authentication is disabled."
        )

    login_rate_limiter: RateLimiter = settings.auth_endpoint_config.rate_limiter
    client_ip = request.client.host if request.client else "unknown"
    rate_key_email = f"login:email:{login_model.email}"
    rate_key_ip = f"login:ip:{client_ip}"

    if await login_rate_limiter.is_blocked(rate_key_email) or await login_rate_limiter.is_blocked(
        rate_key_ip
    ):
        raise HTTPException(
            status_code=429, detail="Too many login attempts. Please try again later."
        )

    auth_result = await authenticate_user(
        login_model.email, login_model.password, settings
    )

    if auth_result is not None:
        await login_rate_limiter.reset(rate_key_email)
        await login_rate_limiter.reset(rate_key_ip)

        if settings.session_storage is not None:
            await settings.session_storage.create(auth_result)

        response.set_cookie(
            key=settings.cookie_name,
            value=auth_result.session_token,
            httponly=True,
            samesite=settings.auth_endpoint_config.samesite,
            secure=settings.auth_endpoint_config.secure,
        )

        return auth_result.user
    else:
        await login_rate_limiter.record_failure(rate_key_email)
        await login_rate_limiter.record_failure(rate_key_ip)
        raise HTTPException(status_code=401, detail="Invalid email or password")

async def logout(request: Request, response: Response, _user = Depends(require_auth())):
    app = request.app
    settings: AuthConfig = app.state.authshield_auth_config
    
    session_token = request.cookies.get(settings.cookie_name)
    if session_token and settings.session_storage is not None:
        await settings.session_storage.delete(session_token)

    response.delete_cookie(key=settings.cookie_name, httponly=True, samesite=settings.auth_endpoint_config.samesite)
    return {"message": "Logged out successfully"}

async def sso_redirect(request: Request, name: str):
    app = request.app
    settings: AuthConfig = app.state.authshield_auth_config
    oauth = app.state.authshield_oauth

    sso_params = settings.auth_endpoint_config.get_sso_provider(name)
    if sso_params is None:
        raise HTTPException(status_code=404, detail=f"SSO provider '{name}' not found")

    response = await getattr(oauth, sso_params.name).authorize_redirect(request, sso_params.oidc_redirect_uri)

    if sso_params.oidc_browser_url is not None:
        current_url = urlparse(response.headers["location"])
        override_url = urlparse(sso_params.oidc_browser_url)

        base_path = override_url.path.rstrip("/")
        target_path = current_url.path.lstrip("/")
        combined_path = f"{base_path}/{target_path}" if base_path else f"/{target_path}"

        new_url = urlunparse((
            override_url.scheme,
            override_url.netloc,
            combined_path,
            current_url.params,
            current_url.query,
            current_url.fragment
        ))

        response.headers["location"] = new_url

    return response

async def sso_login(request: Request, name: str):
    app: FastAPI = request.app
    oauth = app.state.authshield_oauth
    auth_config: AuthConfig = app.state.authshield_auth_config

    sso_params = auth_config.auth_endpoint_config.get_sso_provider(name)
    if sso_params is None:
        raise HTTPException(status_code=404, detail=f"SSO provider '{name}' not found")

    try:
        token = await getattr(oauth, sso_params.name).authorize_access_token(request)
        user_info = await getattr(oauth, sso_params.name).userinfo(token=token)

        if not user_info:
            return RedirectResponse(url=f"{sso_params.browser_failure_redirect}?error=missing_userinfo")

        auth_result = await authenticate_user_by_sso(user_info, auth_config)

        if auth_result is None:
            return RedirectResponse(url=f"{sso_params.browser_failure_redirect}?error=authentication_failed")

        redirect_response = RedirectResponse(url=sso_params.browser_success_redirect)

        if auth_config.session_storage is not None:
            await auth_config.session_storage.create(auth_result)

        redirect_response.set_cookie(
            key=auth_config.cookie_name,
            value=auth_result.session_token,
            httponly=True,
            samesite=auth_config.auth_endpoint_config.samesite,
            secure=auth_config.auth_endpoint_config.secure,
        )
        return redirect_response

    except Exception:
        return RedirectResponse(url=f"{sso_params.browser_failure_redirect}?error=sso_failed")