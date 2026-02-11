from fastapi import Request, HTTPException, Depends
from authlib.integrations.starlette_client import OAuth
from .config import settings
from .jwt_utils import validate_bearer_token
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


async def get_user_from_bearer(request: Request):
    """Attempts to extract and validate a bearer token from Authorization header."""
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return None
    token = auth.split(None, 1)[1]
    try:
        claims = await validate_bearer_token(token)
        # Normalize claims into a user-like dict
        return {
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "preferred_username": claims.get("preferred_username"),
            "roles": claims.get("realm_access", {}).get("roles", []),
            "claims": claims,
        }
    except ValueError:
        return None

def require_auth(user: dict = Depends(get_user)):
    """Blocks access if user is not logged in."""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


async def require_auth_bearer(session_user: dict = Depends(get_user), bearer_user: dict = Depends(get_user_from_bearer)):
    """Composite dependency: accept either session cookie user or validated bearer token."""
    user = session_user or bearer_user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_role(role: str):
    """Factory that returns a dependency verifying the given realm role."""
    def _require(user: dict = Depends(require_auth_bearer)):
        roles = user.get("roles", [])
        if role not in roles:
            logger.warning(f"Unauthorized access attempt by {user.get('preferred_username')} for role {role}")
            raise HTTPException(status_code=403, detail=f"Forbidden: '{role}' role required")
        return user
    return _require


def require_scope(scope: str):
    """Factory that verifies a space-separated scope string in JWT claims."""
    def _require(user: dict = Depends(require_auth_bearer)):
        claims = user.get("claims", {}) or {}
        token_scope = claims.get("scope", "")
        scopes = token_scope.split()
        if scope not in scopes:
            logger.warning(f"Scope '{scope}' required but missing for user {user.get('preferred_username')}")
            raise HTTPException(status_code=403, detail=f"Forbidden: scope '{scope}' required")
        return user
    return _require

def require_manager(user: dict = Depends(require_role("manager"))):
    """Blocks access if user is logged in but lacks 'manager' role."""
    return user

def require_ceo(user: dict = Depends(require_role("ceo"))):
    """Blocks access if user is logged in but lacks 'ceo' role."""
    return user
