import pytest
from pydantic import ValidationError
from app.core.config import Settings


class TestSettingsMetadataUrl:
    def test_metadata_url_construction(self):
        """Test that metadata URL is constructed correctly"""
        settings = Settings(
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="test-realm",
            KEYCLOAK_SERVER_URL="http://keycloak:8080",
        )
        
        expected_url = "http://keycloak:8080/realms/test-realm/.well-known/openid-configuration"
        assert settings.metadata_url == expected_url

    def test_metadata_url_with_custom_server_url(self):
        """Test metadata URL with custom server URL"""
        settings = Settings(
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="my-realm",
            KEYCLOAK_SERVER_URL="https://auth.example.com",
        )
        
        expected_url = "https://auth.example.com/realms/my-realm/.well-known/openid-configuration"
        assert settings.metadata_url == expected_url


class TestSettingsValidation:
    def test_session_secret_key_required_in_production(self):
        """Test that SESSION_SECRET_KEY is required in production"""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                ENV="prod",
                SESSION_SECRET_KEY=None,
                KEYCLOAK_CLIENT_ID="test-client",
                KEYCLOAK_CLIENT_SECRET="test-secret",
                KEYCLOAK_REALM="test-realm",
            )
        
        assert "SESSION_SECRET_KEY must be set in production" in str(exc_info.value)

    def test_session_secret_key_optional_in_dev(self):
        """Test that SESSION_SECRET_KEY is optional in dev"""
        settings = Settings(
            ENV="dev",
            SESSION_SECRET_KEY=None,
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="test-realm",
        )
        
        assert settings.SESSION_SECRET_KEY == "dev-secret-change-me"

    def test_session_secret_key_uses_provided_value(self):
        """Test that provided SESSION_SECRET_KEY is used"""
        settings = Settings(
            ENV="prod",
            SESSION_SECRET_KEY="my-secret-key",
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="test-realm",
        )
        
        assert settings.SESSION_SECRET_KEY == "my-secret-key"


class TestSettingsDefaults:
    def test_default_keycloak_server_url(self):
        """Test that default Keycloak server URL is set"""
        settings = Settings(
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="test-realm",
        )
        
        assert settings.KEYCLOAK_SERVER_URL == "http://localhost:8080"

    def test_default_frontend_url(self):
        """Test that default frontend URL is set"""
        settings = Settings(
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="test-realm",
        )
        
        assert settings.FRONTEND_URL == "http://localhost:5173"

    def test_default_env(self):
        """Test that default ENV is dev"""
        settings = Settings(
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="test-realm",
        )
        
        assert settings.ENV == "dev"


class TestSettingsRequired:
    def test_all_required_fields_present(self):
        """Test that all required Keycloak fields are present in Settings"""
        settings = Settings(
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="test-realm",
        )
        
        assert settings.KEYCLOAK_CLIENT_ID == "test-client"
        assert settings.KEYCLOAK_CLIENT_SECRET == "test-secret"
        assert settings.KEYCLOAK_REALM == "test-realm"

    def test_optional_admin_fields_default_to_none(self):
        """Test that optional admin fields default to None"""
        settings = Settings(
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="test-realm",
        )
        
        assert settings.KEYCLOAK_ADMIN_CLIENT_ID is None
        assert settings.KEYCLOAK_ADMIN_CLIENT_SECRET is None

    def test_admin_fields_can_be_set(self):
        """Test that admin fields can be set when provided"""
        settings = Settings(
            KEYCLOAK_CLIENT_ID="test-client",
            KEYCLOAK_CLIENT_SECRET="test-secret",
            KEYCLOAK_REALM="test-realm",
            KEYCLOAK_ADMIN_CLIENT_ID="admin-client",
            KEYCLOAK_ADMIN_CLIENT_SECRET="admin-secret",
        )
        
        assert settings.KEYCLOAK_ADMIN_CLIENT_ID == "admin-client"
        assert settings.KEYCLOAK_ADMIN_CLIENT_SECRET == "admin-secret"
