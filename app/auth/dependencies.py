from fastapi import Request, HTTPException, Depends
from app.auth.jwt_utils import validate_bearer_token
import logging

logger = logging.getLogger("auth")


def get_session_user(request: Request):
    return request.session.get("user")


async def get_bearer_user(request: Request):
    auth = request.headers.get("Authorization")

    if not auth or not auth.lower().startswith("bearer "):
        return None

    token = auth.split(" ", 1)[1]

    try:
        claims = await validate_bearer_token(token)
        return {
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "preferred_username": claims.get("preferred_username"),
            "name": claims.get("name"),
            "roles": claims.get("realm_access", {}).get("roles", []),
            "claims": claims,
        }
    except ValueError:
        return None


async def require_auth(
    session_user: dict = Depends(get_session_user),
    bearer_user: dict = Depends(get_bearer_user),
):
    user = session_user or bearer_user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_role(role: str):
    """
    Require a specific role.
    Supports:
    - Realm roles
    - Client roles (resource_access)
    """

    def checker(user: dict = Depends(require_auth)):

        # 1️⃣ Realm roles (already stored in session or bearer)
        realm_roles = user.get("roles", []) or []

        # 2️⃣ Client roles (if bearer token with claims)
        client_roles = []
        claims = user.get("claims") or {}

        resource_access = claims.get("resource_access", {})
        if isinstance(resource_access, dict):
            for client_data in resource_access.values():
                client_roles.extend(client_data.get("roles", []))

        # 3️⃣ Combine roles
        all_roles = set(realm_roles + client_roles)

        if role not in all_roles:
            logger.warning(
                f"Unauthorized access by {user.get('preferred_username')} "
                f"for role '{role}'. User roles: {list(all_roles)}"
            )
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: '{role}' role required"
            )

        return user

    return checker
