
from unittest.mock import patch, AsyncMock, MagicMock, PropertyMock
from starlette.requests import Request

@patch("app.api.routes.httpx.AsyncClient")
def test_refresh_success(mock_client, client):
    """
    Test successful token refresh.
    """
    # 1. Use MagicMock for the response (since .json() is synchronous in httpx)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
    "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.YWJj",
    "refresh_token": "new_refresh",
    }
    # 2. Use AsyncMock for the client instance (since .post() is awaited)
    mock_instance = AsyncMock()
    mock_instance.post.return_value = mock_response
    mock_client.return_value.__aenter__.return_value = mock_instance

    # 3. Inject the Session Data
    mock_session_data = {
        "tokens": {"refresh_token": "old_refresh"},
        "user": {"email": "test@example.com"},
    }

    with patch.object(Request, "session", new_callable=PropertyMock) as mock_session:
        mock_session.return_value = mock_session_data
        
        response = client.post("/refresh")

    assert response.status_code == 200
    assert response.json()["message"] == "refreshed"


@patch("app.api.routes.httpx.AsyncClient")
def test_refresh_expired(mock_client, client):
    """
    Test refresh when Keycloak returns an error.
    """
    # Use MagicMock here too for consistency
    mock_response = MagicMock()
    mock_response.status_code = 400

    mock_instance = AsyncMock()
    mock_instance.post.return_value = mock_response
    mock_client.return_value.__aenter__.return_value = mock_instance

    mock_session_data = {"tokens": {"refresh_token": "expired_token"}}

    with patch.object(Request, "session", new_callable=PropertyMock) as mock_session:
        mock_session.return_value = mock_session_data
        
        response = client.post("/refresh")

    assert response.status_code == 401


def test_refresh_no_token(client):
    """
    Test refresh when no session/token exists.
    """
    response = client.post("/refresh")
    assert response.status_code == 401