from fastapi import Request, HTTPException, Depends
import logging
import json

logger = logging.getLogger("auth")

# Cookie name must match routes.py
ACCESS_TOKEN_COOKIE = "access_token"


# async def get_bearer_user(request: Request):
#     """
#     Extract and validate JWT from:
#     1. Authorization header (Bearer token) - for API clients
#     2. httpOnly cookie (access_token) - for browser clients
#     """
#     token = None
    
#     # First, try Authorization header
#     auth = request.headers.get("Authorization")
#     if auth and auth.lower().startswith("bearer "):
#         token = auth.split(" ", 1)[1]
    
#     # Fallback to httpOnly cookie
#     if not token:
#         token = request.cookies.get(ACCESS_TOKEN_COOKIE)

#     if not token:
#         return None

#     try:
#         claims = await validate_bearer_token(token)
#         return {
#             "sub": claims.get("sub"),
#             "email": claims.get("email"),
#             "preferred_username": claims.get("preferred_username"),
#             "name": claims.get("name"),
#             "roles": claims.get("realm_access", {}).get("roles", []),
#             "exp": claims.get("exp"),
#             "claims": claims,
#         }
#     except ValueError:
#         return None


async def get_gateway_user(request: Request):

    user_id = request.headers.get("X-User-ID")

    if not user_id:
        return None

    roles = request.headers.get("X-User-Roles", "[]")

    try:
        roles = json.loads(roles)
    except Exception:
        roles = []

    # Parse token expiry for session timer
    exp = None
    exp_header = request.headers.get("X-Token-Exp")
    if exp_header:
        try:
            exp = int(exp_header)
        except ValueError:
            pass

    return {
        "sub": user_id,
        "email": request.headers.get("X-User-Email"),
        "preferred_username": request.headers.get("X-User-Preferred-Username"),
        "roles": roles,
        "exp": exp,
    }

async def require_auth(user: dict = Depends(get_gateway_user)):
    """Require valid JWT bearer token."""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


# def require_role(role: str):
#     """
#     Require a specific role.
#     Supports:
#     - Realm roles
#     - Client roles (resource_access)
#     """

#     def checker(user: dict = Depends(require_auth)):

#         # 1️⃣ Realm roles
#         realm_roles = user.get("roles", []) or []

#         # 2️⃣ Client roles (if bearer token with claims)
#         client_roles = []
#         claims = user.get("claims") or {}

#         resource_access = claims.get("resource_access", {})
#         if isinstance(resource_access, dict):
#             for client_data in resource_access.values():
#                 client_roles.extend(client_data.get("roles", []))

#         # 3️⃣ Combine roles
#         all_roles = set(realm_roles + client_roles)

#         if role not in all_roles:
#             logger.warning(
#                 f"Unauthorized access by {user.get('preferred_username')} "
#                 f"for role '{role}'. User roles: {list(all_roles)}"
#             )
#             raise HTTPException(
#                 status_code=403,
#                 detail=f"Forbidden: '{role}' role required"
#             )

#         return user

#     return checker


def require_role(role: str):

    def checker(user: dict = Depends(require_auth)):

        roles = user.get("roles", [])

        if role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: '{role}' role required"
            )

        return user

    return checker