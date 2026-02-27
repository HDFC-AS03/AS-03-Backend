# app/services/app_admin_service.py

import httpx
from typing import List, Dict
from app.core.config import settings
from app.services.admin_services import get_admin_token


BASE_ADMIN_URL = (
    f"{settings.KEYCLOAK_SERVER_URL}/admin/realms/{settings.KEYCLOAK_REALM}"
)


async def get_client_uuid(client_id: str, admin_token: str) -> str:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{BASE_ADMIN_URL}/clients",
            headers={"Authorization": f"Bearer {admin_token}"},
            params={"clientId": client_id},
        )
        r.raise_for_status()
        return r.json()[0]["id"]


# -----------------------------------------------------
# BULK CREATE USERS
# -----------------------------------------------------

async def bulk_create_users(users: List[Dict]) -> Dict:
    admin_token = await get_admin_token()
    results = []

    async with httpx.AsyncClient(timeout=10) as client:
        for user in users:
            try:
                r = await client.post(
                    f"{BASE_ADMIN_URL}/users",
                    headers={"Authorization": f"Bearer {admin_token}"},
                    json={
                        "username": user["username"],
                        "email": user["email"],
                        "enabled": True,
                        "credentials": [{
                            "type": "password",
                            "value": user["password"],
                            "temporary": False
                        }]
                    },
                )
                r.raise_for_status()
                results.append({"username": user["username"], "status": "created"})
            except Exception as e:
                results.append({"username": user["username"], "error": str(e)})

    return results


# -----------------------------------------------------
# DELETE USER
# -----------------------------------------------------

async def delete_user(user_id: str) -> None:
    admin_token = await get_admin_token()

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.delete(
            f"{BASE_ADMIN_URL}/users/{user_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        r.raise_for_status()


# -----------------------------------------------------
# GET USERS BY ROLE
# -----------------------------------------------------

async def get_users_by_role(role_name: str) -> List[Dict]:
    admin_token = await get_admin_token()

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{BASE_ADMIN_URL}/roles/{role_name}/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        r.raise_for_status()
        return r.json()


# -----------------------------------------------------
# ASSIGN CLIENT ROLE TO USER
# -----------------------------------------------------

async def assign_role(user_id: str, role_name: str, client_id: str) -> None:
    admin_token = await get_admin_token()
    client_uuid = await get_client_uuid(client_id, admin_token)

    async with httpx.AsyncClient(timeout=10) as client:

        # Get role representation
        role_resp = await client.get(
            f"{BASE_ADMIN_URL}/clients/{client_uuid}/roles/{role_name}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        role_resp.raise_for_status()
        role_data = role_resp.json()

        # Assign role
        assign_resp = await client.post(
            f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/clients/{client_uuid}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=[role_data],
        )
        assign_resp.raise_for_status()