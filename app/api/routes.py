from fastapi import APIRouter, Request, Depends, HTTPException, Response, Header
from fastapi.responses import RedirectResponse
from app.auth.dependencies import require_auth, require_role
from app.core.config import settings
from app.core.response_wrapper import wrap_response
from urllib.parse import urlencode
import httpx
import logging
import os
import secrets
from app.services import app_admin_service
import hashlib
import base64

router = APIRouter()

# Cookie configuration
ACCESS_TOKEN_COOKIE = "access_token"  # httpOnly cookie for access token
REFRESH_TOKEN_COOKIE = "refresh_token"  # httpOnly cookie for refresh token
CSRF_COOKIE_NAME = "csrf_token"
OAUTH_STATE_COOKIE = "oauth_state"  # For PKCE/state during OAuth flow
PKCE_VERIFIER_COOKIE = "pkce_verifier"
ACCESS_TOKEN_MAX_AGE = 60 * 5  # 5 minutes (short-lived)
REFRESH_TOKEN_MAX_AGE = 60 * 60 * 24 * 7  # 7 days
OAUTH_STATE_MAX_AGE = 60 * 5  # 5 minutes for OAuth state
IS_PRODUCTION = os.getenv("ENV", "dev") == "production"

# Always use httpOnly cookies for security (enterprise pattern)
USE_HTTPONLY_COOKIES = True


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
    """
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

# External Keycloak URL for browser redirects
KEYCLOAK_EXTERNAL_URL = os.getenv("KEYCLOAK_EXTERNAL_URL", "http://localhost:8080")


@router.get("/login")
async def login(request: Request):
    """Initiate OAuth flow - stateless using cookie for state storage."""

    audit_logger.info(
        "Login attempt",
        extra={
            "event": "login_attempt",
            "endpoint": "/login",
            "method": request.method,
            "ip": request.client.host,
            "success": True
        },
    )

    try:
        # Generate cryptographic state for CSRF protection
        state = secrets.token_urlsafe(32)

        # PKCE generation
        code_verifier = secrets.token_urlsafe(64)

        challenge = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(challenge).decode().rstrip("=")
        
        # Build callback URL using gateway URL (must match Keycloak valid redirect URIs)
        redirect_uri = f"{settings.GATEWAY_URL}/callback"
        
        # Build Keycloak authorization URL
        auth_params = urlencode({
            "client_id": settings.KEYCLOAK_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        })
        auth_url = f"{KEYCLOAK_EXTERNAL_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/auth?{auth_params}"
        
        # Set state in cookie and redirect
        response = RedirectResponse(url=auth_url)
        # Store PKCE verifier
        response.set_cookie(
            key=PKCE_VERIFIER_COOKIE,
            value=code_verifier,
            httponly=True,
            secure=IS_PRODUCTION,
            samesite="lax",
            max_age=OAUTH_STATE_MAX_AGE,
            path="/",
        )
        response.set_cookie(
            key=OAUTH_STATE_COOKIE,
            value=state,
            httponly=True,
            secure=IS_PRODUCTION,
            samesite="lax",
            max_age=OAUTH_STATE_MAX_AGE,
            path="/",
        )

        audit_logger.info(
            "Login redirect to Keycloak",
            extra={
                "event": "login_redirect",
                "endpoint": "/login",
                "method": request.method,
                "ip": request.client.host,
                "success": True,
            },
        )

        return response

    except Exception as e:
        audit_logger.error(
            "Login failed",
            extra={
                "event": "error",
                "endpoint": "/login",
                "method": request.method,
                "ip": request.client.host,
                "success": False,
                "error": str(e),
            },
        )
        raise


@router.get("/callback", name="auth_callback")
async def auth_callback(request: Request):
    """OAuth callback - validates state from cookie, exchanges code for tokens."""
    # Get code and state from query params
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    audit_logger.info(
        "OAuth callback received",
        extra={
            "event": "login_success",
            "endpoint": "/callback",
            "method": request.method,
            "ip": request.client.host,
            "has_code": bool(code),
            "has_state": bool(state),
            "success": True,
        },
    )
    
    if error:
        audit_logger.error(
            "OAuth callback error",
            extra={
                "event": "error",
                "endpoint": "/callback",
                "method": request.method,
                "ip": request.client.host,
                "success": False,
                "error": error,
            },
        )
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")
    
    # Validate state from cookie
    stored_state = request.cookies.get(OAUTH_STATE_COOKIE)
    if not stored_state:
        raise HTTPException(status_code=400, detail="Missing OAuth state cookie")
    if not secrets.compare_digest(stored_state, state):
        raise HTTPException(status_code=400, detail="Invalid state - possible CSRF attack")


    # Retrieve PKCE verifier
    code_verifier = request.cookies.get(PKCE_VERIFIER_COOKIE)

    if not code_verifier:
        raise HTTPException(status_code=400, detail="Missing PKCE verifier")
    
    # Exchange code for tokens
    # redirect_uri = str(request.url_for("auth_callback"))
    redirect_uri = f"{settings.GATEWAY_URL}/callback"
    token_url = f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    
    async with httpx.AsyncClient(timeout=10) as client:
        token_response = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": settings.KEYCLOAK_CLIENT_ID,
                "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )
    
    if token_response.status_code != 200:
        audit_logger.error(
            "Token exchange failed",
            extra={
                "event": "error",
                "endpoint": "/callback",
                "method": request.method,
                "status_code": token_response.status_code,
                "success": False,
                "error": token_response.text,
            },
        )
        raise HTTPException(status_code=401, detail="Token exchange failed")
    
    tokens = token_response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token")
    
    # Enterprise pattern: Store BOTH tokens in httpOnly cookies, redirect without tokens in URL
    response = RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard")
    
    # Set access_token in httpOnly cookie (short-lived)
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        httponly=True,
        secure=IS_PRODUCTION,  # HTTPS only in production
        samesite="lax",
        max_age=ACCESS_TOKEN_MAX_AGE,
        path="/",
    )
    
    # Set refresh_token in httpOnly cookie (longer-lived)
    if refresh_token:
        response.set_cookie(
            key=REFRESH_TOKEN_COOKIE,
            value=refresh_token,
            httponly=True,
            secure=IS_PRODUCTION,
            samesite="lax",
            max_age=REFRESH_TOKEN_MAX_AGE,
            path="/",
        )
    
    # Set CSRF token cookie (readable by JS for double-submit pattern)
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,  # Must be readable by JavaScript
        secure=IS_PRODUCTION,
        samesite="lax",
        max_age=REFRESH_TOKEN_MAX_AGE,
        path="/",
    )
    
    # Clear the oauth_state cookie
    response.delete_cookie(key=OAUTH_STATE_COOKIE, path="/")
    response.delete_cookie(key=PKCE_VERIFIER_COOKIE, path="/")
    return response


# External Keycloak URL for browser redirects
KEYCLOAK_EXTERNAL_URL = os.getenv("KEYCLOAK_EXTERNAL_URL", "http://localhost:8080")
# Keycloak URL reachable from Docker for refresh token calls
KEYCLOAK_REFRESH_URL = os.getenv("KEYCLOAK_REFRESH_URL", "http://host.docker.internal:8080")

@router.get("/logout")
async def logout(request: Request):
    audit_logger.info(
        "Logout initiated",
        extra={
            "event": "logout",
            "endpoint": "/logout",
            "method": request.method,
            "ip": request.client.host,
            "success": True,
        },
    )
    """Logout: clear all auth cookies and redirect to Keycloak logout."""
    logout_url = (
        f"{KEYCLOAK_EXTERNAL_URL}/realms/"
        f"{settings.KEYCLOAK_REALM}/protocol/openid-connect/logout"
    )

    response = RedirectResponse(
        f"{logout_url}?post_logout_redirect_uri="
        f"{settings.FRONTEND_URL}&client_id={settings.KEYCLOAK_CLIENT_ID}"
    )
    
    # Clear the httpOnly access_token cookie
    response.delete_cookie(
        key=ACCESS_TOKEN_COOKIE,
        path="/",
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="lax",
    )
    
    # Clear the httpOnly refresh_token cookie
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE,
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
async def get_current_user(
    request: Request,  
    user: dict = Depends(require_auth)
):
    audit_logger.info(
        "User info accessed",
        extra={
            "event": "user_activity",
            "endpoint": request.url.path,
            "method": request.method,
            "status_code": 200,
            "ip": request.client.host,
            "user_id": user.get("sub"),
            "success": True,
        },
    )
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
    audit_logger.info(
        "Refresh attempt",
        extra={
            "event": "token_refresh",
            "endpoint": "/refresh",
            "method": request.method,
            "ip": request.client.host,
            "success": True,
        },
    )

    
    try:
        """
        Refresh access token using httpOnly refresh_token cookie.
        Returns new access_token in httpOnly cookie (browser) or JSON (API clients).
        """
        # Read refresh_token from httpOnly cookie
        refresh_token_value = request.cookies.get(REFRESH_TOKEN_COOKIE)
        if not refresh_token_value:
            audit_logger.error(
                "Refresh failed - no cookie",
                extra={
                    "event": "error",
                    "endpoint": "/refresh",
                    "method": request.method,
                    "ip": request.client.host,
                    "status_code": 401,
                    "success": False,
                    "error": "No refresh token cookie",
                },
            )
            raise HTTPException(status_code=401, detail="No refresh token cookie")

        # Use KEYCLOAK_REFRESH_URL - backend can reach host.docker.internal:8080
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
            audit_logger.error(
                "Refresh failed - invalid/expired token",
                extra={
                    "event": "error",
                    "endpoint": "/refresh",
                    "method": request.method,
                    "ip": request.client.host,
                    "status_code": keycloak_response.status_code,
                    "success": False,
                    "error": keycloak_response.text,
                },
            )
            # Clear invalid cookies
            response.delete_cookie(key=ACCESS_TOKEN_COOKIE, path="/")
            response.delete_cookie(key=REFRESH_TOKEN_COOKIE, path="/")
            raise HTTPException(status_code=401, detail="Refresh token expired or invalid")

        new_tokens = keycloak_response.json()
        new_access_token = new_tokens.get("access_token")
        new_refresh_token = new_tokens.get("refresh_token")
        
        # Update access_token cookie
        response.set_cookie(
            key=ACCESS_TOKEN_COOKIE,
            value=new_access_token,
            httponly=True,
            secure=IS_PRODUCTION,
            samesite="lax",
            max_age=ACCESS_TOKEN_MAX_AGE,
            path="/",
        )
        
        # Update refresh_token cookie (token rotation)
        if new_refresh_token:
            response.set_cookie(
                key=REFRESH_TOKEN_COOKIE,
                value=new_refresh_token,
                httponly=True,
                secure=IS_PRODUCTION,
                samesite="lax",
                max_age=REFRESH_TOKEN_MAX_AGE,
                path="/",
            )
        
        # Rotate CSRF token on successful refresh
        new_csrf = generate_csrf_token()
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=new_csrf,
            httponly=False,
            secure=IS_PRODUCTION,
            samesite="lax",
            max_age=REFRESH_TOKEN_MAX_AGE,
            path="/",
        )

        audit_logger.info(
            "Token refreshed successfully",
            extra={
                "event": "token_refresh",
                "endpoint": "/refresh",
                "method": request.method,
                "status_code": 200,
                "ip": request.client.host,
                "success": True,
            },
        )

        return {"success": True, "message": "Token refreshed"}

    except HTTPException as e:
        audit_logger.error(
            "Refresh failed",
            extra={
                "event": "error",
                "endpoint": "/refresh",
                "method": request.method,
                "status_code": e.status_code,
                "ip": request.client.host,
                "success": False,
                "error": str(e.detail),
            },
        )
        raise



# -------------------------
# BULK CREATE USERS (IMPROVED)
# -------------------------
@router.post("/admin/bulk-users")
async def bulk_users(
    payload: list[dict],
    user: dict = Depends(require_role("admin"))
):
    audit_logger.info(
        "Bulk user creation attempt",
        extra={
            "event": "admin_action",
            "action": "bulk_create_users",
            "admin_id": user.get("sub"),
            "count": len(payload),
            "success": True,
        },
    )
    result = await app_admin_service.bulk_create_users(payload)
    audit_logger.info(
        "Bulk user creation success",
        extra={
            "event": "admin_action",
            "action": "bulk_create_users",
            "admin_id": user.get("sub"),
            "count": len(payload),
            "success": True,
        },
    )
    return wrap_response(result, message="Bulk user operation completed")


# -------------------------
# DELETE USER
# -------------------------
@router.delete("/admin/users/{user_id}")
async def remove_user(
    user_id: str,
    user: dict = Depends(require_role("admin"))
):

    audit_logger.info(
        "User deletion attempt",
        extra={
            "event": "admin_action",
            "action": "delete_user",
            "admin_id": user.get("sub"),
            "target_user": user_id,
            "success": True,
        },
    )

    await app_admin_service.delete_user(user_id)

    audit_logger.info(
        "User deleted successfully",
        extra={
            "event": "admin_action",
            "action": "delete_user",
            "admin_id": user.get("sub"),
            "target_user": user_id,
            "success": True,
        },
    )
    return wrap_response({}, message="User deleted successfully")


# -------------------------
# VIEW USERS
# -------------------------
@router.get("/admin/users")
async def view_users(
    request: Request,
    user: dict = Depends(require_role("admin"))
):
    audit_logger.info(
        "View users",
        extra={
            "event": "admin_action",
            "action": "view_users",
            "method": request.method,
            "endpoint": request.url.path,
            "admin_id": user.get("sub"),
            "ip": request.client.host,
            "success": True,
        },
    )
    # Fetch all users from Keycloak (includes those without roles)
    all_users = await app_admin_service.get_all_users()
    
    # Exclude the current admin user from the list
    current_user_id = user.get("sub")
    filtered_users = [u for u in all_users if u.get("id") != current_user_id]
    
    return wrap_response(filtered_users, message="Users fetched successfully")


# -------------------------
# ASSIGN ROLE
# -------------------------
audit_logger = logging.getLogger("audit")


@router.post("/admin/users/{user_id}/roles")
async def assign_role_api(
    user_id: str,
    role_name: str,
    request: Request,
    user: dict = Depends(require_role("admin"))
):

    # 🔹 BEFORE → intent
    audit_logger.info(
        "Role assignment attempt",
        extra={
            "event": "admin_action",
            "action": "assign_role",
            "admin_id": user.get("sub"),
            "target_user": user_id,
            "role": role_name,
            "endpoint": request.url.path,
            "method": request.method,
            "ip": request.client.host,
            "success": True,
        },
    )

    try:
        # 🔹 MAIN ACTION (only once)
        await app_admin_service.assign_role(
            user_id,
            role_name,
            settings.KEYCLOAK_CLIENT_ID
        )

        # 🔹 SUCCESS
        audit_logger.info(
            "Role assigned successfully",
            extra={
                "event": "admin_action",
                "action": "assign_role",
                "admin_id": user.get("sub"),
                "target_user": user_id,
                "role": role_name,
                "status_code": 200,
                "success": True,
            },
        )

        return wrap_response({}, message="Role assigned successfully")

    except Exception as e:
        # 🔹 FAILURE
        audit_logger.error(
            "Role assignment failed",
            extra={
                "event": "error",
                "action": "assign_role",
                "admin_id": user.get("sub"),
                "target_user": user_id,
                "role": role_name,
                "endpoint": request.url.path,
                "method": request.method,
                "ip": request.client.host,
                "success": False,
                "error": str(e),
            },
        )
        raise


# -------------------------
# REMOVE ROLE
# -------------------------
@router.delete("/admin/users/{user_id}/roles")
async def remove_role_api(
    user_id: str,
    role_name: str,
    user: dict = Depends(require_role("admin"))
):

    audit_logger.info(
        "Role removal attempt",
        extra={
            "event": "admin_action",
            "action": "remove_role",
            "admin_id": user.get("sub"),
            "target_user": user_id,
            "role": role_name,
            "success": True,
        },
    )

    await app_admin_service.remove_role(user_id, role_name, settings.KEYCLOAK_CLIENT_ID)

    audit_logger.info(
        "Role removed successfully",
        extra={
            "event": "admin_action",
            "action": "remove_role",
            "admin_id": user.get("sub"),
            "target_user": user_id,
            "role": role_name,
            "success": True,
        },
    )

    return wrap_response({}, message="Role removed successfully")


# -------------------------
# UPDATE ROLE
# -------------------------
@router.put("/admin/users/{user_id}/roles")
async def update_role_api(
    user_id: str,
    old_role: str,
    new_role: str,
    user: dict = Depends(require_role("admin"))
):

    audit_logger.info(
        "Role update attempt",
        extra={
            "event": "admin_action",
            "action": "update_role",
            "admin_id": user.get("sub"),
            "target_user": user_id,
            "old_role": old_role,
            "new_role": new_role,
            "success": True,
        },
    )

    await app_admin_service.update_role(user_id, old_role, new_role, settings.KEYCLOAK_CLIENT_ID)

    audit_logger.info(
        "Role updated successfully",
        extra={
            "event": "admin_action",
            "action": "update_role",
            "admin_id": user.get("sub"),
            "target_user": user_id,
            "old_role": old_role,
            "new_role": new_role,
            "success": True,
        },
    )

    return wrap_response({}, message="Role updated successfully")


# -------------------------
# USER ACCOUNT CONSOLE
# -------------------------
@router.get("/account")
async def redirect_to_account_console(
    user: dict = Depends(require_auth)
):
    account_url = (
        f"{KEYCLOAK_EXTERNAL_URL}/realms/"
        f"{settings.KEYCLOAK_REALM}/account"
    )

    return RedirectResponse(account_url)


# -------------------------
# ADMIN CONSOLE
# -------------------------
@router.get("/admin/console")
async def redirect_to_admin_console(
    user: dict = Depends(require_role("admin"))
):
    admin_console_url = (
        f"{KEYCLOAK_EXTERNAL_URL}/admin/"
        f"{settings.KEYCLOAK_REALM}/console/"
    )

    return RedirectResponse(admin_console_url)

# -------------------------
# GET USER ROLES
# -------------------------
@router.get("/admin/users/{user_id}/roles")
async def get_user_roles_api(
    user_id: str,
    user: dict = Depends(require_role("admin"))
):

    audit_logger.info(
        "Fetch user roles",
        extra={
            "event": "admin_action",
            "action": "get_user_roles",
            "admin_id": user.get("sub"),
            "target_user": user_id,
            "success": True,
        },
    )
    roles = await app_admin_service.get_user_roles(user_id)
    return wrap_response(roles, message="User roles fetched successfully")