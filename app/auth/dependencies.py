from fastapi import Request, HTTPException, Depends
import logging
import json
import time

logger = logging.getLogger("auth")

# Cookie name must match routes.py
ACCESS_TOKEN_COOKIE = "access_token"


async def get_gateway_user(request: Request):
    """
    Extract user information from gateway headers.
    
    🔐 SECURITY: The gateway MUST authenticate itself before we trust these headers.
    Without this validation, anyone can spoof user identity.
    
    Attack scenario (BLOCKED):
    - Attacker: curl -H "X-User-ID: admin" http://api/me
    - Result: 401 Unauthorized (gateway not authenticated)
    
    Legitimate scenario (ALLOWED):
    - Gateway: curl -H "X-User-ID: admin" -H "X-Gateway-Secret: <secret>" http://api/me
    - Result: 200 OK (gateway authenticated, user returned)
    """
    from app.core.config import settings
    
    # 🔒 CRITICAL: Validate gateway authentication first
    if settings.GATEWAY_SECRET:
        gateway_secret = request.headers.get("X-Gateway-Secret")
        if not gateway_secret or gateway_secret != settings.GATEWAY_SECRET:
            # ❌ Gateway did not authenticate itself
            # Don't trust these headers - reject immediately
            logger.warning(f"Rejected request without valid gateway secret from {request.client}")
            return None
    else:
        # Dev mode: no gateway secret configured
        # In production, GATEWAY_SECRET MUST be set in environment
        logger.warning("⚠️  No GATEWAY_SECRET configured - header spoofing possible!")

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