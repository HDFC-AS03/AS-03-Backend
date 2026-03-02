# app/services/app_admin_service.py

import httpx
from typing import List, Dict, Optional
from app.core.config import settings
from app.services.admin_services import get_admin_token

BASE_ADMIN_URL = (
    f"{settings.KEYCLOAK_SERVER_URL}/admin/realms/{settings.KEYCLOAK_REALM}"
)


async def get_client_uuid(client_id: str, admin_token: str) -> str:
    """
    Helper to get the internal UUID of a client (e.g. 'fastapi-app') 
    needed for role mapping.
    """
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{BASE_ADMIN_URL}/clients",
            headers={"Authorization": f"Bearer {admin_token}"},
            params={"clientId": client_id},
        )
        r.raise_for_status()
        clients = r.json()
        if not clients:
            raise ValueError(f"Client ID '{client_id}' not found in realm.")
        return clients[0]["id"]


# -----------------------------------------------------
# GET ALL USERS
# -----------------------------------------------------

async def get_all_users() -> List[Dict]:
    admin_token = await get_admin_token()

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{BASE_ADMIN_URL}/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            params={"max": 200},
        )
        r.raise_for_status()
        raw_users = r.json()

    normalized = []
    for u in raw_users:
        full_name = f"{u.get('firstName', '')} {u.get('lastName', '')}".strip()
        normalized.append({
            "id":      u["id"],
            "name":    full_name or u.get("username", ""),
            "email":   u.get("email", ""),
            "role":    "User",  # You might want to fetch actual roles here if needed
            "status":  "Active" if u.get("enabled") else "Inactive",
            "created": u.get("createdTimestamp", ""), # Timestamp format usually needs parsing on frontend
            "av":      u.get("username", "??")[:2].upper(),
        })

    return normalized


# -----------------------------------------------------
# BULK CREATE USERS
# -----------------------------------------------------

async def bulk_create_users(users: List[Dict]) -> List[Dict]:
    admin_token = await get_admin_token()
    results = []

    async with httpx.AsyncClient(timeout=10) as client:
        for user in users:
            # Basic validation
            if not user.get("username") and user.get("email"):
                 user["username"] = user["email"].split("@")[0]

            try:
                payload = {
                    "username": user["username"],
                    "email": user["email"],
                    "enabled": user.get("enabled", True),
                    "credentials": [{
                        "type": "password",
                        "value": user.get("password", "ChangeMe123!"),
                        "temporary": False
                    }]
                }

                # Handle name splitting if provided
                if "name" in user:
                    parts = user["name"].strip().split(" ")
                    payload["firstName"] = parts[0]
                    if len(parts) > 1:
                        payload["lastName"] = " ".join(parts[1:])

                r = await client.post(
                    f"{BASE_ADMIN_URL}/users",
                    headers={"Authorization": f"Bearer {admin_token}"},
                    json=payload,
                )
                
                # If user already exists, Keycloak returns 409
                if r.status_code == 409:
                    results.append({"username": user["username"], "error": "User already exists"})
                    continue
                
                r.raise_for_status()
                
                # Get the ID of the created user to return it (optional but helpful)
                loc = r.headers.get("Location")
                new_id = loc.split("/")[-1] if loc else None
                
                results.append({
                    "username": user["username"], 
                    "status": "created",
                    "id": new_id
                })

            except Exception as e:
                results.append({"username": user.get("username", "unknown"), "error": str(e)})

    return results


# -----------------------------------------------------
# UPDATE USER (NEW)
# -----------------------------------------------------

async def update_user(user_id: str, data: Dict) -> None:
    admin_token = await get_admin_token()
    
    payload = {}
    
    # Handle Name splitting (Full Name -> First + Last)
    if "name" in data and data["name"]:
        parts = data["name"].strip().split(" ")
        payload["firstName"] = parts[0]
        payload["lastName"] = " ".join(parts[1:]) if len(parts) > 1 else ""
        
    # Handle Email
    if "email" in data:
        payload["email"] = data["email"]
        
    # Handle Status (Active/Inactive)
    if "status" in data:
        payload["enabled"] = (data["status"] == "Active")

    if not payload:
        return # Nothing to update

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.put(
            f"{BASE_ADMIN_URL}/users/{user_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=payload,
        )
        r.raise_for_status()


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
        if r.status_code == 404:
            return # User already gone
            
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
    
    # 1. Get the UUID for the client (e.g. "fastapi-app")
    client_uuid = await get_client_uuid(client_id, admin_token)

    async with httpx.AsyncClient(timeout=10) as client:

        # 2. Get the specific role definition from Keycloak
        role_resp = await client.get(
            f"{BASE_ADMIN_URL}/clients/{client_uuid}/roles/{role_name}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        
        if role_resp.status_code == 404:
            raise ValueError(f"Role '{role_name}' not found in client '{client_id}'")
            
        role_resp.raise_for_status()
        role_data = role_resp.json()

        # 3. Assign that role to the user
        assign_resp = await client.post(
            f"{BASE_ADMIN_URL}/users/{user_id}/role-mappings/clients/{client_uuid}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=[role_data],
        )
        assign_resp.raise_for_status()