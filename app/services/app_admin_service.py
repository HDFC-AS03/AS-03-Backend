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

                if not r.is_success:
                    print(f"Keycloak error: {r.status_code} - {r.text}")
                r.raise_for_status()

                user_id = r.headers.get("Location").split("/")[-1]

                # ── ROLE ASSIGNMENT ──────────────────────────
                role_name = user.get("role")
                if role_name:
                    role_resp = await client.get(
                        f"{BASE_ADMIN_URL}/roles/{role_name}",
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    if role_resp.status_code == 200:
                        await client.post(
                            f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/realm",
                            headers={"Authorization": f"Bearer {admin_token}"},
                            json=[role_resp.json()],
                        )
                # ─────────────────────────────────────────────

                await client.put(
                    f"{BASE_ADMIN_URL}/users/{user_id}/send-verify-email",
                    headers={"Authorization": f"Bearer {admin_token}"}
                )

                results.append({
                    "username": user["username"],
                    "status": "created",
                    "role_assigned": role_name or None,
                    "verification_email_sent": True
                })

            except Exception as e:
                results.append({
                    "username": user.get("username"),
                    "status": "failed",
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
async def assign_role(user_id: str, role_name: str, client_id: str = None) -> None:
    admin_token = await get_admin_token()
    async with httpx.AsyncClient(timeout=10) as client:
        # Get realm role representation
        role_resp = await client.get(
            f"{BASE_ADMIN_URL}/roles/{role_name}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        role_resp.raise_for_status()
        role_data = role_resp.json()

        assign_resp = await client.post(
            f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/realm",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=[role_data],
        )
        assign_resp.raise_for_status()


async def remove_role(user_id: str, role_name: str, client_id: str = None) -> None:
    admin_token = await get_admin_token()
    async with httpx.AsyncClient(timeout=10) as client:
        # 1. Fetch the role representation
        role_resp = await client.get(
            f"{BASE_ADMIN_URL}/roles/{role_name}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        role_resp.raise_for_status()
        role_data = role_resp.json()

        # 2. Use client.request() instead of client.delete() to pass a JSON body
        delete_resp = await client.request(
            method="DELETE",
            url=f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/realm",
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