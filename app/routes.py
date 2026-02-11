import json
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.exceptions import HTTPException
import httpx
from .auth import oauth, require_manager, require_ceo, require_role, require_auth_bearer
from .config import settings
from .admin import sync_users, get_user_by_id

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    user = request.session.get("user")

    if not user:
        return '<a href="/login">Login with Keycloak</a>'

    roles = user.get("roles", [])
    name = user.get("preferred_username") or user.get("email") or "User"

    menu = ""

    if "manager" in roles:
        menu += '<li><a href="/manager">Manager Dashboard</a></li>'

    if "ceo" in roles:
        menu += '<li><a href="/ceo">CEO Dashboard</a></li>'

    return f"""
    <h1>Welcome, {name}</h1>
    <p>Roles: {roles}</p>
    <ul>
        {menu}
        <li><a href="/logout">Logout</a></li>
    </ul>
    """


@router.get("/login")
async def login(request: Request):
    # Ensure redirect_uri uses https if running behind a proxy (handled by request.url_for)
    redirect_uri = request.url_for('auth_callback')
    return await oauth.keycloak.authorize_redirect(request, redirect_uri)

@router.get("/callback", name="auth_callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.keycloak.authorize_access_token(request)

        # TEMP: inspect access token
        access_token = token["access_token"]
        print("ACCESS TOKEN:\n", access_token)

        request.session["user"] = token.get("userinfo")
        return RedirectResponse(url="/")

    except Exception as e:
        return HTMLResponse(f"Auth failed: {e}", status_code=400)

@router.get("/logout")
async def logout(request: Request):
    request.session.pop('user', None)
    
    # Redirect to Keycloak's logout endpoint
    logout_url = f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/logout"
    redirect_param = str(request.url_for('homepage'))
    
    return RedirectResponse(f"{logout_url}?post_logout_redirect_uri={redirect_param}&client_id={settings.KEYCLOAK_CLIENT_ID}")

@router.get("/manager")
async def manager_dashboard(user: dict = Depends(require_manager)):
    return HTMLResponse("<h1>Manager Dashboard</h1><p>Welcome, Admin!</p>")

@router.get("/ceo")
def ceo_dashboard(user: dict = Depends(require_ceo)):
    return {
        "msg": f"Welcome CEO {user.get('preferred_username') or user.get('email')}"
    }


@router.get("/api/data")
async def api_data(user: dict = Depends(require_role("manager"))):
    """Example API endpoint protected by bearer token or session requiring 'manager' role."""
    return {"data": "sensitive-data", "user": user.get("preferred_username")}


@router.post("/admin/sync-users")
async def admin_sync(user: dict = Depends(require_role("admin"))):
    """Admin endpoint: trigger user sync from Keycloak admin API.

    Requires the caller to have `admin` realm role.
    """
    result = await sync_users()
    return result


@router.get("/admin/user/{user_id}")
async def admin_get_user(user_id: str, user: dict = Depends(require_role("admin"))):
    """Admin endpoint: fetch a single user by id from Keycloak admin API."""
    info = await get_user_by_id(user_id)
    if not info:
        return {"ok": False, "reason": "not found"}
    return {"ok": True, "user": info}

@router.get("/me")
async def get_current_user(user: dict = Depends(require_auth_bearer)):
    """
    Get current authenticated user's details (name, email, roles, groups).
    
    This endpoint is called by the frontend to display user info in the app shell.
    It works with both session cookies (browser login) and bearer tokens (API calls).
    
    Returns:
    - sub: Unique user ID from Keycloak
    - email: User's email address
    - preferred_username: Username/login name
    - name: Full name (if available)
    - roles: List of realm roles assigned to user (e.g., ['manager', 'user'])
    - groups: List of groups user belongs to (if groups are mapped in Keycloak)
    
    Example response:
    {
        "sub": "user-uuid-123",
        "email": "john@example.com",
        "preferred_username": "john.smith",
        "name": "John Smith",
        "roles": ["manager", "user"],
        "groups": ["sales-team"]
    }
    """
    return {
        "sub": user.get("sub"),
        "email": user.get("email"),
        "preferred_username": user.get("preferred_username"),
        "name": user.get("name"),
        "roles": user.get("roles", []),
        "groups": user.get("groups", []),
    }


@router.post("/refresh")
async def refresh_token(request: Request):
    """
    Securely refresh an expired access token using a refresh token.
    
    This endpoint is called by the frontend when the access token expires (401).
    The frontend sends the refresh_token (obtained during login), and this endpoint
    exchanges it for a new access_token.
    
    SECURITY: The client_secret is kept on the backend (never exposed to frontend).
    This is more secure than frontend calling Keycloak directly.
    
    Request body:
    {
        "refresh_token": "long-lived-token-from-login"
    }
    
    Returns:
    {
        "access_token": "new-short-lived-token",
        "refresh_token": "new-or-same-refresh-token",
        "expires_in": 900,  # 15 minutes in seconds
        "token_type": "Bearer"
    }
    
    Usage (Frontend):
    1. Store refresh_token securely after login
    2. When access_token expires (401 response), call this endpoint
    3. Use returned access_token for subsequent API calls
    """
    try:
        # Parse request body
        body = await request.json()
        refresh_token_value = body.get("refresh_token")
        
        if not refresh_token_value:
            raise HTTPException(
                status_code=400,
                detail="refresh_token required in request body"
            )
        
        # Call Keycloak token endpoint to exchange refresh token for new access token
        token_url = f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
        
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "refresh_token",
                    "client_id": settings.KEYCLOAK_CLIENT_ID,
                    "client_secret": settings.KEYCLOAK_CLIENT_SECRET,  # Secure: backend only!
                    "refresh_token": refresh_token_value,
                },
            )
        
        # Handle Keycloak errors (invalid refresh token, expired, etc.)
        if response.status_code != 200:
            raise HTTPException(
                status_code=401,
                detail="Token refresh failed: invalid or expired refresh_token"
            )
        
        # Return new tokens to frontend
        return response.json()
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Token refresh error: {str(e)}"
        )


@router.get("/health")
async def health_check():
    """Important for Docker/Kubernetes readiness probes"""
    return {"status": "ok"}