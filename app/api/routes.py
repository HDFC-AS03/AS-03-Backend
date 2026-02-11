from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from app.auth.oauth import oauth
from app.auth.dependencies import require_auth, require_role
from app.core.config import settings
from jose import jwt
import json

router = APIRouter()

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
    decoded = jwt.get_unverified_claims(access_token)

    print("\n========== DECODED ACCESS TOKEN ==========")
    print(json.dumps(decoded, indent=4))
    print("==========================================\n")

    # Extract roles properly
    roles = decoded.get("realm_access", {}).get("roles", [])

    # Build proper session user object
    request.session["user"] = {
        "sub": decoded.get("sub"),
        "email": decoded.get("email"),
        "preferred_username": decoded.get("preferred_username"),
        "name": decoded.get("name"),
        "roles": roles,
    }

    return RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard")


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()

    logout_url = (
        f"{settings.KEYCLOAK_SERVER_URL}/realms/"
        f"{settings.KEYCLOAK_REALM}/protocol/openid-connect/logout"
    )

    return RedirectResponse(
        f"{logout_url}?post_logout_redirect_uri="
        f"{settings.FRONTEND_URL}&client_id={settings.KEYCLOAK_CLIENT_ID}"
    )


@router.get("/me")
async def get_current_user(user: dict = Depends(require_auth)):
    return {
        "sub": user.get("sub"),
        "email": user.get("email"),
        "preferred_username": user.get("preferred_username"),
        "name": user.get("name"),
        "roles": user.get("roles", []),
    }


@router.get("/admin")
async def admin_only(user: dict = Depends(require_role("admin"))):
    return {"message": "Admin access granted"}


@router.get("/health")
async def health():
    return {"status": "ok"}
