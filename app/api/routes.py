from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from app.auth.oauth import oauth
from app.auth.dependencies import require_auth, require_role
from app.core.config import settings
from app.core.response_wrapper import wrap_response
from jose import jwt
from app.services import app_admin_service
# import json
# from fastapi import Body
import httpx

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
    print("----- CALLBACK DEBUG -----")
    print("SESSION:", dict(request.session))
    print("QUERY STATE:", request.query_params.get("state"))
    print("--------------------------")
    token = await oauth.keycloak.authorize_access_token(request)

    access_token = token["access_token"]
    refresh_token = token.get("refresh_token")

    decoded = jwt.get_unverified_claims(access_token)

    roles = decoded.get("realm_access", {}).get("roles", [])

    # Store user
    request.session["user"] = {
        "sub": decoded.get("sub"),
        "email": decoded.get("email"),
        "preferred_username": decoded.get("preferred_username"),
        "name": decoded.get("name"),
        "roles": roles,
        "exp": decoded.get("exp"),
    }

    # Store tokens securely in session
    request.session["tokens"] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
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
async def refresh_token(request: Request):
    tokens = request.session.get("tokens")

    if not tokens or not tokens.get("refresh_token"):
        request.session.clear()
        raise HTTPException(status_code=401, detail="No refresh token")

    refresh_token_value = tokens.get("refresh_token")

    token_url = (
        f"{settings.KEYCLOAK_SERVER_URL}/realms/"
        f"{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    )

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "client_id": settings.KEYCLOAK_CLIENT_ID,
                "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
                "refresh_token": refresh_token_value,
            },
        )

    if response.status_code != 200:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Refresh expired")

    new_tokens = response.json()

    # Update session tokens
    request.session["tokens"] = {
        "access_token": new_tokens.get("access_token"),
        "refresh_token": new_tokens.get("refresh_token"),
    }

    # Update expiry
    decoded = jwt.get_unverified_claims(new_tokens.get("access_token"))

    user = request.session.get("user", {})
    user["exp"] = decoded.get("exp")
    request.session["user"] = user

    return {"message": "refreshed"}
#-------------------
#Add bulk users
#------------------
@router.post("/admin/bulk-users")
async def bulk_users(
    payload: list[dict],
    user: dict = Depends(require_role("admin"))
):
    result = await app_admin_service.bulk_create_users(payload)
    return wrap_response(result, message="Bulk user operation completed")
#-----------------
# DELETE USER ROUTE
# ----------------
@router.delete("/admin/users/{user_id}")
async def remove_user(
    user_id: str,
    user: dict = Depends(require_role("admin"))
):
    await app_admin_service.delete_user(user_id)
    return wrap_response({}, message="User deleted successfully")
#--------------
#View Users (By roles) 
#---------------
@router.get("/admin/users")
async def view_users(
    user: dict = Depends(require_role("admin"))
):
    users = await app_admin_service.get_users_by_role("user")
    return wrap_response(users, message="Users fetched successfully")
#-------------------
#ASSIGN ROLE
#---------------------
@router.post("/admin/users/{user_id}/roles")
async def assign_role_api(
    user_id: str,
    role_name: str,
    user: dict = Depends(require_role("admin"))
):
    await app_admin_service.assign_role(
        user_id,
        role_name,
        "fast-api-client"
    )
    return wrap_response({}, message="Role assigned successfully")
