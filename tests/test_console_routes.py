def test_account_redirect(client, override_auth):

    response = client.get("/account", follow_redirects=False)

    assert response.status_code in (302, 307)


def test_admin_console_redirect(client, override_auth):

    response = client.get("/admin/console", follow_redirects=False)

    assert response.status_code in (302, 307)