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
# BULK CREATE USERS (IMPROVED)
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
                        "emailVerified": False,
                        "requiredActions": [
                            "VERIFY_EMAIL",
                            "UPDATE_PASSWORD"
                        ]
                    },
                )

                r.raise_for_status()

                user_id = r.headers.get("Location").split("/")[-1]

                await client.put(
                    f"{BASE_ADMIN_URL}/users/{user_id}/send-verify-email",
                    headers={"Authorization": f"Bearer {admin_token}"}
                )

                results.append({
                    "username": user["username"],
                    "status": "created",
                    "verification_email_sent": True
                })

            except Exception as e:
                results.append({
                    "username": user.get("username"),
                    "error": str(e)
                })

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
# ASSIGN CLIENT ROLE
# -----------------------------------------------------
async def assign_role(user_id: str, role_name: str, client_id: str) -> None:

    admin_token = await get_admin_token()
    client_uuid = await get_client_uuid(client_id, admin_token)

    async with httpx.AsyncClient(timeout=10) as client:

        role_resp = await client.get(
            f"{BASE_ADMIN_URL}/clients/{client_uuid}/roles/{role_name}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        role_resp.raise_for_status()
        role_data = role_resp.json()

        assign_resp = await client.post(
            f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/clients/{client_uuid}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=[role_data],
        )

        assign_resp.raise_for_status()


# -----------------------------------------------------
# REMOVE CLIENT ROLE
# -----------------------------------------------------
async def remove_role(user_id: str, role_name: str, client_id: str) -> None:

    admin_token = await get_admin_token()
    client_uuid = await get_client_uuid(client_id, admin_token)

    async with httpx.AsyncClient(timeout=10) as client:

        role_resp = await client.get(
            f"{BASE_ADMIN_URL}/clients/{client_uuid}/roles/{role_name}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        role_resp.raise_for_status()
        role_data = role_resp.json()

        delete_resp = await client.delete(
            f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/clients/{client_uuid}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=[role_data],
        )

        delete_resp.raise_for_status()


# -----------------------------------------------------
# UPDATE ROLE
# -----------------------------------------------------
async def update_role(
    user_id: str,
    old_role: str,
    new_role: str,
    client_id: str
) -> None:

    await remove_role(user_id, old_role, client_id)
    await assign_role(user_id, new_role, client_id)
    
#------------------------------
# Fetch User Roles
#------------------------------ 
async def get_user_roles(user_id: str) -> List[Dict]:
    admin_token = await get_admin_token()
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/realm",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        r.raise_for_status()
        return r.json()