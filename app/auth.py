from fastapi import Request, HTTPException, Depends
from authlib.integrations.starlette_client import OAuth
from .config import settings
import logging

# 1. Setup Logging
logger = logging.getLogger("auth")

# 2. Setup OAuth
oauth = OAuth()
oauth.register(
    name='keycloak',
    client_id=settings.KEYCLOAK_CLIENT_ID,
    client_secret=settings.KEYCLOAK_CLIENT_SECRET,
    server_metadata_url=settings.metadata_url,
    client_kwargs={
        'scope': 'openid email profile',
    }
)

# 3. Dependencies (RBAC Logic)

def get_user(request: Request):
    """Retrieves user data from the session."""
    return request.session.get('user')

def require_auth(user: dict = Depends(get_user)):
    """Blocks access if user is not logged in."""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

def require_manager(user: dict = Depends(require_auth)):
    """Blocks access if user is logged in but lacks 'manager' role."""
    roles = user.get('roles', [])
    if 'manager' not in roles:
        logger.warning(f"Unauthorized access attempt by {user.get('preferred_username')}")
        raise HTTPException(status_code=403, detail="Forbidden: 'manager' role required")
    return user