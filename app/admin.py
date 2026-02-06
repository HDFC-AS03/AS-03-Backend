from typing import List, Dict, Any, Optional
import logging
import httpx
from .config import settings

logger = logging.getLogger("admin")

async def get_admin_token() -> Optional[str]:
    """Obtain an admin access token using client_credentials grant.

    Requires `KEYCLOAK_ADMIN_CLIENT_ID` and `KEYCLOAK_ADMIN_CLIENT_SECRET`.
    Returns `access_token` string or None if not configured.
    """
    client_id = settings.KEYCLOAK_ADMIN_CLIENT_ID
    client_secret = settings.KEYCLOAK_ADMIN_CLIENT_SECRET
    if not client_id or not client_secret:
        logger.warning("Admin client not configured; cannot obtain admin token")
        return None

    token_url = f"{settings.KEYCLOAK_SERVER_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(token_url, data=data)
        r.raise_for_status()
        j = r.json()
        return j.get("access_token")


async def fetch_users(admin_token: str) -> List[Dict[str, Any]]:
    """Fetch users from Keycloak Admin REST API for the configured realm."""
    url = f"{settings.KEYCLOAK_SERVER_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users"
    headers = {"Authorization": f"Bearer {admin_token}"}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        return r.json()


async def sync_users() -> Dict[str, Any]:
    """High-level helper to get admin token and fetch users. Returns summary dict."""
    token = await get_admin_token()
    if not token:
        return {"ok": False, "reason": "admin client not configured"}
    users = await fetch_users(token)
    # Here you would typically sync into your DB. For now return summary.
    return {"ok": True, "user_count": len(users)}


async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    token = await get_admin_token()
    if not token:
        return None
    url = f"{settings.KEYCLOAK_SERVER_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url, headers=headers)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
