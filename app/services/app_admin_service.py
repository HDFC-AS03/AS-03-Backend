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

                # Handle duplicate user (409 Conflict)
                if r.status_code == 409:
                    results.append({
                        "username": user["username"],
                        "status": "failed",
                        "error": "User already exists"
                    })
                    continue

                r.raise_for_status()

                user_id = r.headers.get("Location").split("/")[-1]

                # Assign the requested role (default to "user" if not specified)
                role_name = user.get("role", "user")
                try:
                    role_resp = await client.get(
                        f"{BASE_ADMIN_URL}/roles/{role_name}",
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    role_resp.raise_for_status()
                    role_data = role_resp.json()

                    await client.post(
                        f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/realm",
                        headers={"Authorization": f"Bearer {admin_token}"},
                        json=[role_data],
                    )
                except Exception:
                    pass  # Role assignment is optional

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
# GET ALL USERS
# -----------------------------------------------------
async def get_all_users() -> List[Dict]:
    """Fetch all users from Keycloak (excluding service accounts)."""
    admin_token = await get_admin_token()

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{BASE_ADMIN_URL}/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            params={"max": 1000},  # Adjust as needed
        )
        r.raise_for_status()
        
        # Filter out service accounts and admin users
        users = r.json()
        return [u for u in users if not u.get("serviceAccountClientId")]


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
# ASSIGN REALM ROLE
# -----------------------------------------------------
async def assign_role(user_id: str, role_name: str, client_id: str = None) -> None:
    """Assign a realm-level role to a user."""
    admin_token = await get_admin_token()

    async with httpx.AsyncClient(timeout=10) as client:
        # Get the realm role
        role_resp = await client.get(
            f"{BASE_ADMIN_URL}/roles/{role_name}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        role_resp.raise_for_status()
        role_data = role_resp.json()

        # Assign realm role to user
        assign_resp = await client.post(
            f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/realm",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=[role_data],
        )
        assign_resp.raise_for_status()


# -----------------------------------------------------
# REMOVE REALM ROLE
# -----------------------------------------------------
async def remove_role(user_id: str, role_name: str, client_id: str = None) -> None:
    """Remove a realm-level role from a user."""
    admin_token = await get_admin_token()

    async with httpx.AsyncClient(timeout=10) as client:
        # Get the realm role
        role_resp = await client.get(
            f"{BASE_ADMIN_URL}/roles/{role_name}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        role_resp.raise_for_status()
        role_data = role_resp.json()

        # Remove realm role from user (use request() since delete() doesn't support json body)
        delete_resp = await client.request(
            method="DELETE",
            url=f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/realm",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=[role_data],
        )
        delete_resp.raise_for_status()


# -----------------------------------------------------
# UPDATE ROLE (REPLACE)
# -----------------------------------------------------
async def update_role(
    user_id: str,
    old_role: str,
    new_role: str,
    client_id: str = None
) -> None:
    """Replace one realm role with another."""
    await remove_role(user_id, old_role)
    await assign_role(user_id, new_role)
    
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