from unittest.mock import patch, AsyncMock


# -------------------------
# BULK CREATE USERS
# -------------------------
@patch("app.api.routes.app_admin_service.bulk_create_users", new_callable=AsyncMock)
def test_bulk_users(mock_bulk, client, override_auth):

    mock_bulk.return_value = [
        {"username": "user1", "status": "created"}
    ]

    payload = [
        {"username": "user1", "email": "user1@test.com"}
    ]

    response = client.post("/admin/bulk-users", json=payload)

    assert response.status_code == 200
    assert response.json()["message"] == "Bulk user operation completed"


# -------------------------
# DELETE USER
# -------------------------
@patch("app.api.routes.app_admin_service.delete_user", new_callable=AsyncMock)
def test_delete_user(mock_delete, client, override_auth):

    response = client.delete("/admin/users/test-id")

    assert response.status_code == 200
    assert response.json()["message"] == "User deleted successfully"


# -------------------------
# VIEW USERS
# -------------------------
@patch("app.api.routes.app_admin_service.get_users_by_role", new_callable=AsyncMock)
def test_view_users(mock_get_users, client, override_auth):

    mock_get_users.return_value = [
        {"id": "1", "username": "testuser"}
    ]

    response = client.get("/admin/users")

    assert response.status_code == 200
    assert response.json()["message"] == "Users fetched successfully"


# -------------------------
# ASSIGN ROLE
# -------------------------
@patch("app.api.routes.app_admin_service.assign_role", new_callable=AsyncMock)
def test_assign_role(mock_assign, client, override_auth):

    response = client.post("/admin/users/test-id/roles?role_name=admin")

    assert response.status_code == 200
    assert response.json()["message"] == "Role assigned successfully"


# -------------------------
# REMOVE ROLE
# -------------------------
@patch("app.api.routes.app_admin_service.remove_role", new_callable=AsyncMock)
def test_remove_role(mock_remove, client, override_auth):

    response = client.delete("/admin/users/test-id/roles?role_name=admin")

    assert response.status_code == 200
    assert response.json()["message"] == "Role removed successfully"


# -------------------------
# UPDATE ROLE
# -------------------------
@patch("app.api.routes.app_admin_service.update_role", new_callable=AsyncMock)
def test_update_role(mock_update, client, override_auth):

    response = client.put(
        "/admin/users/test-id/roles?old_role=user&new_role=admin"
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Role updated successfully"