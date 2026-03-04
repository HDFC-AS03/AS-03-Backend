from fastapi import APIRouter, Request, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse
from app.auth.oauth import oauth
from app.auth.dependencies import require_auth, require_role
from app.core.config import settings
from app.core.response_wrapper import wrap_response
from jose import jwt
import httpx
import os

router = APIRouter()

# Cookie configuration
COOKIE_NAME = "refresh_token"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days
IS_PRODUCTION = os.getenv("ENV", "dev") == "production"

# Development vs Production token handling:
# - DEV: Both tokens in URL hash (stored in sessionStorage) - XSS risk but works cross-port
# - PROD: Access token in URL, refresh token in httpOnly cookie (requires same-origin)
USE_COOKIE_REFRESH = IS_PRODUCTION

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
async def logout(request: Request):
    request.session.clear()

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
async def refresh_token(request: Request, response: Response):
    """
    Refresh access token.
    - Production: reads refresh_token from httpOnly cookie
    - Development: reads refresh_token from request body
    Returns new access_token (and refresh_token in dev mode).
    """
    import logging
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
            logging.info(f"Refresh token received (first 50 chars): {refresh_token_value[:50] if refresh_token_value else 'None'}...")
        except Exception as e:
            logging.error(f"Failed to parse refresh body: {e}")
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
        import logging
        logging.error(f"Keycloak refresh failed: {keycloak_response.status_code} - {keycloak_response.text}")
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
        return {"access_token": new_tokens.get("access_token")}
    else:
        # Development: Return both tokens
        return {
            "access_token": new_tokens.get("access_token"),
            "refresh_token": new_tokens.get("refresh_token"),
        }

