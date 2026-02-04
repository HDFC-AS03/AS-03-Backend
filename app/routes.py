import json
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from .auth import oauth, require_manager
from .config import settings

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    user = request.session.get('user')
    if user:
        return f"""
        <h1>Welcome, {user.get('preferred_username')}</h1>
        <p>Roles: {user.get('roles', [])}</p>
        <ul>
            <li><a href="/manager">Manager Dashboard</a></li>
            <li><a href="/logout">Logout</a></li>
        </ul>
        """
    return '<a href="/login">Login with Keycloak</a>'

@router.get("/login")
async def login(request: Request):
    # Ensure redirect_uri uses https if running behind a proxy (handled by request.url_for)
    redirect_uri = request.url_for('auth_callback')
    return await oauth.keycloak.authorize_redirect(request, redirect_uri)

@router.get("/callback", name="auth_callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.keycloak.authorize_access_token(request)
        request.session['user'] = token.get('userinfo')
        return RedirectResponse(url='/')
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

@router.get("/health")
async def health_check():
    """Important for Docker/Kubernetes readiness probes"""
    return {"status": "ok"}