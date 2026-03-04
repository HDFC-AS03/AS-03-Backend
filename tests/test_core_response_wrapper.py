import pytest
from datetime import datetime, timezone
from app.core.response_wrapper import wrap_response


class TestWrapResponse:
    def test_wrap_response_basic_structure(self):
        """Test that response has correct basic structure"""
        result = wrap_response(data={"id": 1}, message="Success")
        
        assert result["success"] is True
        assert result["message"] == "Success"
        assert result["data"] == {"id": 1}
        assert "metadata" in result
        assert "timestamp" in result["metadata"]
        assert "version" in result["metadata"]

    def test_wrap_response_default_values(self):
        """Test that default values are applied correctly"""
        result = wrap_response(data=None)
        
        assert result["success"] is True
        assert result["message"] == "Success"
        assert result["data"] is None
        assert result["metadata"]["version"] == "1.0"

    def test_wrap_response_custom_message(self):
        """Test that custom message is used"""
        result = wrap_response(data={}, message="Custom message")
        
        assert result["message"] == "Custom message"

    def test_wrap_response_custom_success_flag(self):
        """Test that custom success flag is used"""
        result = wrap_response(data={}, success=False)
        
        assert result["success"] is False

    def test_wrap_response_custom_version(self):
        """Test that custom version is used"""
        result = wrap_response(data={}, version="2.0")
        
        assert result["metadata"]["version"] == "2.0"

    def test_wrap_response_timestamp_format(self):
        """Test that timestamp is in ISO format with Z suffix"""
        result = wrap_response(data={})
        
        timestamp = result["metadata"]["timestamp"]
        assert timestamp.endswith("Z")
        # Verify it's a valid ISO format
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    def test_wrap_response_with_ttl(self):
        """Test that TTL is included when provided"""
        result = wrap_response(data={}, ttl=3600)
        
        assert "ttl" in result["metadata"]
        assert result["metadata"]["ttl"]["value"] == 3600
        assert result["metadata"]["ttl"]["unit"] == "seconds"
        assert "expires_at" in result["metadata"]["ttl"]

    def test_wrap_response_ttl_expiration_time(self):
        """Test that TTL expiration time is calculated correctly"""
        ttl_seconds = 3600
        result = wrap_response(data={}, ttl=ttl_seconds)
        
        timestamp = datetime.fromisoformat(
            result["metadata"]["timestamp"].replace("Z", "+00:00")
        )
        expires_at = datetime.fromisoformat(
            result["metadata"]["ttl"]["expires_at"].replace("Z", "+00:00")
        )
        
        # Check that expiration is approximately ttl_seconds in the future
        diff = (expires_at - timestamp).total_seconds()
        assert abs(diff - ttl_seconds) < 1  # Allow 1 second tolerance

    def test_wrap_response_without_ttl(self):
        """Test that TTL is not included when not provided"""
        result = wrap_response(data={})
        
        assert "ttl" not in result["metadata"]

    def test_wrap_response_with_complex_data(self):
        """Test that complex data structures are preserved"""
        complex_data = {
            "users": [
                {"id": 1, "name": "John"},
                {"id": 2, "name": "Jane"},
            ],
            "meta": {"total": 2},
        }
        result = wrap_response(data=complex_data)
        
        assert result["data"] == complex_data

    def test_wrap_response_with_null_data(self):
        """Test that null data is handled correctly"""
        result = wrap_response(data=None)
        
        assert result["data"] is None

    def test_wrap_response_with_empty_list(self):
        """Test that empty list is handled correctly"""
        result = wrap_response(data=[])
        
        assert result["data"] == []

    def test_wrap_response_with_zero_ttl(self):
        """Test that zero TTL is handled correctly"""
        result = wrap_response(data={}, ttl=0)
        
        assert result["metadata"]["ttl"]["value"] == 0
        # Expiration should be at approximately the same time as timestamp
        timestamp = datetime.fromisoformat(
            result["metadata"]["timestamp"].replace("Z", "+00:00")
        )
        expires_at = datetime.fromisoformat(
            result["metadata"]["ttl"]["expires_at"].replace("Z", "+00:00")
        )
        diff = (expires_at - timestamp).total_seconds()
        assert abs(diff) < 1

    def test_wrap_response_error_response(self):
        """Test that error response can be created"""
        result = wrap_response(
            data=None,
            message="User not found",
            success=False,
        )
        
        assert result["success"] is False
        assert result["message"] == "User not found"
        assert result["data"] is None

    def test_wrap_response_with_error_details(self):
        """Test that error details can be included in data"""
        error_data = {
            "error_code": "USER_NOT_FOUND",
            "details": "The requested user does not exist",
        }
        result = wrap_response(
            data=error_data,
            message="Error",
            success=False,
        )
        
        assert result["data"] == error_data
        assert result["success"] is False
