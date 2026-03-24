"""
Tests for core configuration.
"""
import pytest
import os
from unittest.mock import patch
from app.core.config import Settings


class TestSettingsConfiguration:
    """Tests for Settings configuration class."""
    
    def test_settings_loads_from_env(self):
        """Test that settings loads from environment variables."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
            "KEYCLOAK_SERVER_URL": "http://keycloak:8080",
        }):
            settings = Settings()
            
            assert settings.KEYCLOAK_CLIENT_ID == "test-client"
            assert settings.KEYCLOAK_CLIENT_SECRET == "test-secret"
            assert settings.KEYCLOAK_REALM == "test-realm"
            assert settings.KEYCLOAK_SERVER_URL == "http://keycloak:8080"
    
    def test_settings_default_values(self):
        """Test that settings has correct default values."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
        }, clear=True):
            settings = Settings()
            
            assert settings.KEYCLOAK_SERVER_URL == "http://localhost:8080"
            assert settings.FRONTEND_URL == "http://localhost:3000"
            assert settings.GATEWAY_URL == "http://localhost"
            assert settings.ENV == "dev"
    
    def test_settings_env_variable(self):
        """Test that ENV variable is configurable."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
            "ENV": "production",
        }):
            settings = Settings()
            
            assert settings.ENV == "production"
    
    def test_settings_optional_admin_credentials(self):
        """Test that admin credentials are optional."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
        }, clear=True):
            settings = Settings()
            
            assert settings.KEYCLOAK_ADMIN_CLIENT_ID is None
            assert settings.KEYCLOAK_ADMIN_CLIENT_SECRET is None
    
    def test_settings_admin_credentials_when_provided(self):
        """Test that admin credentials are used when provided."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
            "KEYCLOAK_ADMIN_CLIENT_ID": "admin-client",
            "KEYCLOAK_ADMIN_CLIENT_SECRET": "admin-secret",
        }):
            settings = Settings()
            
            assert settings.KEYCLOAK_ADMIN_CLIENT_ID == "admin-client"
            assert settings.KEYCLOAK_ADMIN_CLIENT_SECRET == "admin-secret"
    
    def test_settings_metadata_url_property(self):
        """Test that metadata_url property is constructed correctly."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
            "KEYCLOAK_SERVER_URL": "http://keycloak:8080",
        }):
            settings = Settings()
            
            expected_url = (
                "http://keycloak:8080/realms/"
                "test-realm/.well-known/openid-configuration"
            )
            assert settings.metadata_url == expected_url
    
    def test_settings_metadata_url_with_default_server(self):
        """Test metadata_url with default server URL."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "my-realm",
        }, clear=True):
            settings = Settings()
            
            expected_url = (
                "http://localhost:8080/realms/"
                "my-realm/.well-known/openid-configuration"
            )
            assert settings.metadata_url == expected_url
    
    def test_settings_frontend_url_custom(self):
        """Test that FRONTEND_URL can be customized."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
            "FRONTEND_URL": "https://app.example.com",
        }):
            settings = Settings()
            
            assert settings.FRONTEND_URL == "https://app.example.com"
    
    def test_settings_gateway_url_custom(self):
        """Test that GATEWAY_URL can be customized."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
            "GATEWAY_URL": "https://api.example.com",
        }):
            settings = Settings()
            
            assert settings.GATEWAY_URL == "https://api.example.com"
    
    def test_settings_required_fields_validation(self):
        """Test that required fields are validated."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            # Missing KEYCLOAK_CLIENT_SECRET and KEYCLOAK_REALM
        }, clear=True):
            with pytest.raises(Exception):  # Pydantic validation error
                Settings()
    
    def test_settings_ignores_extra_env_variables(self):
        """Test that extra environment variables are ignored."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
            "EXTRA_VAR": "should-be-ignored",
            "ANOTHER_EXTRA": "also-ignored",
        }):
            settings = Settings()
            
            # Should not raise error and should load successfully
            assert settings.KEYCLOAK_CLIENT_ID == "test-client"
            assert not hasattr(settings, "EXTRA_VAR")
            assert not hasattr(settings, "ANOTHER_EXTRA")
    
    def test_settings_keycloak_server_url_custom(self):
        """Test that KEYCLOAK_SERVER_URL can be customized."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
            "KEYCLOAK_SERVER_URL": "https://keycloak.example.com",
        }):
            settings = Settings()
            
            assert settings.KEYCLOAK_SERVER_URL == "https://keycloak.example.com"
    
    def test_settings_multiple_instances_independent(self):
        """Test that multiple Settings instances are independent."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "client1",
            "KEYCLOAK_CLIENT_SECRET": "secret1",
            "KEYCLOAK_REALM": "realm1",
        }):
            settings1 = Settings()
        
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "client2",
            "KEYCLOAK_CLIENT_SECRET": "secret2",
            "KEYCLOAK_REALM": "realm2",
        }):
            settings2 = Settings()
        
        assert settings1.KEYCLOAK_CLIENT_ID == "client1"
        assert settings2.KEYCLOAK_CLIENT_ID == "client2"
    
    def test_settings_metadata_url_format(self):
        """Test that metadata_url has correct format."""
        with patch.dict(os.environ, {
            "KEYCLOAK_CLIENT_ID": "test-client",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REALM": "test-realm",
            "KEYCLOAK_SERVER_URL": "http://keycloak:8080",
        }):
            settings = Settings()
            
            url = settings.metadata_url
            assert url.startswith("http://keycloak:8080/realms/")
            assert "test-realm" in url
            assert url.endswith("/.well-known/openid-configuration")
