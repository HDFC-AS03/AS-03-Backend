from fastapi import APIRouter, Request, Depends, HTTPException, Response, Header
from fastapi.responses import RedirectResponse
from app.auth.oauth import oauth
from app.auth.dependencies import require_auth, require_role
from app.core.config import settings
from app.core.response_wrapper import wrap_response
import httpx
import logging
import os
import secrets

router = APIRouter()

# Cookie configuration
COOKIE_NAME = "refresh_token"
CSRF_COOKIE_NAME = "csrf_token"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days
IS_PRODUCTION = os.getenv("ENV", "dev") == "production"

# Development vs Production token handling:
# - DEV: Both tokens in URL hash (stored in sessionStorage) - XSS risk but works cross-port
# - PROD: Access token in URL, refresh token in httpOnly cookie (requires same-origin)
USE_COOKIE_REFRESH = IS_PRODUCTION


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


async def validate_csrf(
    request: Request,
    x_csrf_token: str | None = Header(None, alias="X-CSRF-Token"),
):
    """
    CSRF validation dependency for state-changing endpoints.
    Validates that X-CSRF-Token header matches csrf_token cookie.
    Only enforced in production mode with httpOnly cookies.
    """
    if not USE_COOKIE_REFRESH:
        # Skip CSRF in dev mode (no httpOnly cookies)
        return True
    
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    
    if not csrf_cookie:
        raise HTTPException(status_code=403, detail="Missing CSRF cookie")
    
    if not x_csrf_token:
        raise HTTPException(status_code=403, detail="Missing X-CSRF-Token header")
    
    if not secrets.compare_digest(csrf_cookie, x_csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")
    
    return True

@router.get("/")
async def root():
    return {"message": "Auth Service Running"}

@router.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for("auth_callback")
    return await oauth.keycloak.authorize_redirect(request, redirect_uri)


@router.get("/callback", name="auth_callback")
async def auth_callback(request: Request):
    token = await oauth.keycloak.authorize_access_token(request)

    access_token = token["access_token"]
    refresh_token = token.get("refresh_token")

    from urllib.parse import urlencode
    
    if USE_COOKIE_REFRESH:
        # Production: Only access_token in URL, refresh token in httpOnly cookie
        token_params = urlencode({"access_token": access_token})
        response = RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard#{token_params}")
        
        if refresh_token:
            response.set_cookie(
                key=COOKIE_NAME,
                value=refresh_token,
                httponly=True,
                secure=True,  # Requires HTTPS in production
                samesite="lax",
                max_age=COOKIE_MAX_AGE,
                path="/",
            )
        
        # Set CSRF token cookie (readable by JS for double-submit pattern)
        csrf_token = generate_csrf_token()
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            httponly=False,  # Must be readable by JavaScript
            secure=True,
            samesite="lax",
            max_age=COOKIE_MAX_AGE,
            path="/",
        )
    else:
        # Development: Both tokens in URL (frontend stores in sessionStorage)
        token_params = urlencode({
            "access_token": access_token,
            "refresh_token": refresh_token or "",
        })
        response = RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard#{token_params}")
    
    return response


# External Keycloak URL for browser redirects
KEYCLOAK_EXTERNAL_URL = os.getenv("KEYCLOAK_EXTERNAL_URL", "http://localhost:8080")
# Keycloak URL reachable from Docker for refresh token calls
KEYCLOAK_REFRESH_URL = os.getenv("KEYCLOAK_REFRESH_URL", "http://host.docker.internal:8080")

@router.get("/logout")
async def logout():
    """Logout: clear cookies and redirect to Keycloak logout."""
    logout_url = (
        f"{KEYCLOAK_EXTERNAL_URL}/realms/"
        f"{settings.KEYCLOAK_REALM}/protocol/openid-connect/logout"
    )

    response = RedirectResponse(
        f"{logout_url}?post_logout_redirect_uri="
        f"{settings.FRONTEND_URL}&client_id={settings.KEYCLOAK_CLIENT_ID}"
    )
    
    # Clear the httpOnly refresh_token cookie
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/",
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="lax",
    )
    
    # Clear the CSRF token cookie
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        httponly=False,
        secure=IS_PRODUCTION,
        samesite="lax",
    )
    
    return response


@router.get("/me")
async def get_current_user(user: dict = Depends(require_auth)):
    user_data = {
        "sub": user.get("sub"),
        "email": user.get("email"),
        "preferred_username": user.get("preferred_username"),
        "name": user.get("name"),
        "roles": user.get("roles", []),
        "exp": user.get("exp"),
    }

    return wrap_response(
        user_data,
        message="User information retrieved successfully",
        ttl=300,
    )


@router.get("/admin")
async def admin_only(user: dict = Depends(require_role("admin"))):
    return {"message": "Admin access granted"}


@router.get("/health")
async def health():
    return {"status": "ok"}



@router.post("/refresh")
async def refresh_token(
    request: Request,
    response: Response,
    _csrf: bool = Depends(validate_csrf),
):
    """
    Refresh access token.
    - Production: reads refresh_token from httpOnly cookie, requires CSRF token
    - Development: reads refresh_token from request body
    Returns new access_token (and refresh_token in dev mode).
    """
    refresh_token_value = None
    
    if USE_COOKIE_REFRESH:
        # Production: Read from httpOnly cookie
        refresh_token_value = request.cookies.get(COOKIE_NAME)
        if not refresh_token_value:
            raise HTTPException(status_code=401, detail="No refresh token cookie")
    else:
        # Development: Read from request body
        try:
            body = await request.json()
            refresh_token_value = body.get("refresh_token")
        except Exception:
            pass
        if not refresh_token_value:
            raise HTTPException(status_code=400, detail="refresh_token required in body")

    # Use KEYCLOAK_REFRESH_URL - backend can reach host.docker.internal:8080
    # Tokens are issued by localhost:8080, but Keycloak accepts refresh from same realm
    token_url = (
        f"{KEYCLOAK_REFRESH_URL}/realms/"
        f"{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    )

    async with httpx.AsyncClient(timeout=10) as client:
        keycloak_response = await client.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "client_id": settings.KEYCLOAK_CLIENT_ID,
                "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
                "refresh_token": refresh_token_value,
            },
        )

    if keycloak_response.status_code != 200:
        logging.warning(f"Refresh failed: {keycloak_response.status_code}")
        if USE_COOKIE_REFRESH:
            response.delete_cookie(key=COOKIE_NAME, path="/")
        raise HTTPException(status_code=401, detail="Refresh token expired or invalid")

    new_tokens = keycloak_response.json()
    
    if USE_COOKIE_REFRESH:
        # Production: Update httpOnly cookie, return only access_token
        new_refresh_token = new_tokens.get("refresh_token")
        if new_refresh_token:
            response.set_cookie(
                key=COOKIE_NAME,
                value=new_refresh_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=COOKIE_MAX_AGE,
                path="/",
            )
        
        # Rotate CSRF token on successful refresh
        new_csrf = generate_csrf_token()
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=new_csrf,
            httponly=False,
            secure=True,
            samesite="lax",
            max_age=COOKIE_MAX_AGE,
            path="/",
        )
        
        return {"access_token": new_tokens.get("access_token"), "csrf_token": new_csrf}
    else:
        # Development: Return both tokens
        return {
            "access_token": new_tokens.get("access_token"),
            "refresh_token": new_tokens.get("refresh_token"),
        }

