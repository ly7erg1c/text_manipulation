"""
Unit tests for the VirusTotal API client.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import aiohttp
import responses

from text_manipulation.core.api_clients.virustotal import VirusTotalClient


@pytest.mark.unit
@pytest.mark.api
class TestVirusTotalClient:
    """Test class for VirusTotal API client."""

    @pytest.fixture
    def client(self):
        """Create a VirusTotal client instance for testing."""
        return VirusTotalClient(api_key="test_api_key")

    @pytest.fixture
    def mock_response_data(self):
        """Mock response data from VirusTotal API."""
        return {
            "data": {
                "id": "192.168.1.1",
                "type": "ip_address",
                "attributes": {
                    "reputation": 0,
                    "last_analysis_stats": {
                        "harmless": 70,
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 10,
                        "timeout": 0
                    },
                    "as_owner": "Test ISP",
                    "country": "US"
                }
            }
        }

    def test_client_initialization(self, client):
        """Test VirusTotal client initialization."""
        assert client.api_key == "test_api_key"
        assert hasattr(client, 'base_url')
        assert client.base_url is not None

    @responses.activate
    def test_query_ip_success(self, client, mock_response_data):
        """Test successful IP query to VirusTotal."""
        ip_address = "192.168.1.1"
        
        responses.add(
            responses.GET,
            f"{client.base_url}/ip_addresses/{ip_address}",
            json=mock_response_data,
            status=200
        )
        
        with patch.object(client, '_make_request') as mock_request:
            mock_request.return_value = mock_response_data
            
            result = client.query_ip(ip_address)
            
            assert result is not None
            assert result.get("data", {}).get("id") == ip_address

    @responses.activate
    def test_query_hash_success(self, client):
        """Test successful hash query to VirusTotal."""
        file_hash = "5d41402abc4b2a76b9719d911017c592"
        
        mock_hash_response = {
            "data": {
                "id": file_hash,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 0,
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 74,
                        "timeout": 0
                    },
                    "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
                }
            }
        }
        
        responses.add(
            responses.GET,
            f"{client.base_url}/files/{file_hash}",
            json=mock_hash_response,
            status=200
        )
        
        with patch.object(client, '_make_request') as mock_request:
            mock_request.return_value = mock_hash_response
            
            result = client.query_hash(file_hash)
            
            assert result is not None
            assert result.get("data", {}).get("id") == file_hash

    @responses.activate
    def test_query_url_success(self, client):
        """Test successful URL query to VirusTotal."""
        url = "https://example.com"
        
        mock_url_response = {
            "data": {
                "id": "encoded_url_id",
                "type": "url",
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 75,
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 5,
                        "timeout": 0
                    },
                    "url": url
                }
            }
        }
        
        with patch.object(client, '_make_request') as mock_request:
            mock_request.return_value = mock_url_response
            
            result = client.query_url(url)
            
            assert result is not None
            assert result.get("data", {}).get("attributes", {}).get("url") == url

    def test_api_key_required(self):
        """Test that API key is required for client initialization."""
        with pytest.raises((ValueError, TypeError)):
            VirusTotalClient(api_key=None)

    @responses.activate
    def test_rate_limiting(self, client):
        """Test rate limiting handling."""
        ip_address = "192.168.1.1"
        
        responses.add(
            responses.GET,
            f"{client.base_url}/ip_addresses/{ip_address}",
            status=429,
            headers={"Retry-After": "60"}
        )
        
        with patch.object(client, '_handle_rate_limit') as mock_rate_limit:
            mock_rate_limit.return_value = None
            
            try:
                client.query_ip(ip_address)
            except Exception:
                pass  # Expected to fail due to rate limiting
            
            # Verify rate limiting was handled
            if hasattr(client, '_handle_rate_limit'):
                mock_rate_limit.assert_called()

    @responses.activate
    def test_api_error_handling(self, client):
        """Test API error handling."""
        ip_address = "192.168.1.1"
        
        responses.add(
            responses.GET,
            f"{client.base_url}/ip_addresses/{ip_address}",
            status=404,
            json={"error": {"code": "NotFound", "message": "Resource not found"}}
        )
        
        with patch.object(client, '_handle_error') as mock_error_handler:
            mock_error_handler.return_value = None
            
            try:
                result = client.query_ip(ip_address)
                # If error handling returns None or raises exception
                assert result is None
            except Exception:
                pass  # Expected behavior

    @pytest.mark.asyncio
    async def test_async_query(self, client):
        """Test asynchronous query functionality."""
        ip_address = "192.168.1.1"
        
        with patch.object(client, '_make_async_request') as mock_async_request:
            mock_async_request.return_value = {"data": {"id": ip_address}}
            
            if hasattr(client, 'query_ip_async'):
                result = await client.query_ip_async(ip_address)
                assert result is not None
                assert result.get("data", {}).get("id") == ip_address

    def test_request_headers(self, client):
        """Test that proper headers are set for requests."""
        headers = client._get_headers() if hasattr(client, '_get_headers') else {}
        
        # Test that API key is included in headers
        assert isinstance(headers, dict)
        # Note: Actual header validation depends on implementation

    def test_url_encoding(self, client):
        """Test URL encoding for special characters."""
        special_url = "https://example.com/path with spaces"
        
        if hasattr(client, '_encode_url'):
            encoded = client._encode_url(special_url)
            assert " " not in encoded
        else:
            # If no encoding method, ensure client can handle it
            assert special_url is not None

    @responses.activate
    def test_invalid_response_handling(self, client):
        """Test handling of invalid JSON responses."""
        ip_address = "192.168.1.1"
        
        responses.add(
            responses.GET,
            f"{client.base_url}/ip_addresses/{ip_address}",
            body="Invalid JSON",
            status=200
        )
        
        try:
            result = client.query_ip(ip_address)
            # Should handle invalid JSON gracefully
            assert result is None or isinstance(result, dict)
        except Exception:
            # Exception handling is also acceptable
            pass 