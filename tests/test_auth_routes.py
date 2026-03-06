def test_me_authenticated(client, override_auth):
    response = client.get("/me")
    assert response.status_code == 200
    assert response.json()["data"]["email"] == "test@example.com"
def test_admin_access(client, override_auth):
    response = client.get("/admin")
    assert response.status_code == 200
    assert response.json()["message"] == "Admin access granted"
def test_logout(client):
    response = client.get("/logout", follow_redirects=False)
    assert response.status_code in (302, 307)
