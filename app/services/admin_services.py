from typing import List, Dict, Any, Optional
import httpx
from app.core.config import settings


async def get_admin_token() -> Optional[str]:
    if not settings.KEYCLOAK_ADMIN_CLIENT_ID:
        return None

    token_url = (
        f"{settings.KEYCLOAK_SERVER_URL}/realms/"
        f"{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    )

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.KEYCLOAK_ADMIN_CLIENT_ID,
                "client_secret": settings.KEYCLOAK_ADMIN_CLIENT_SECRET,
            },
        )
        r.raise_for_status()
        return r.json().get("access_token")


async def fetch_users(admin_token: str) -> List[Dict[str, Any]]:
    url = (
        f"{settings.KEYCLOAK_SERVER_URL}/admin/realms/"
        f"{settings.KEYCLOAK_REALM}/users"
    )

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            url,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        r.raise_for_status()
        return r.json()
