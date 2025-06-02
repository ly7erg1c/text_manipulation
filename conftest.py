"""
Pytest configuration and shared fixtures for the text manipulation tool.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch
import asyncio
import os
import sys

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from text_manipulation.core.config import Config
from text_manipulation.cli.interface import TextManipulationCLI


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_config():
    """Provide a test configuration."""
    config = Config()
    config.debug = True
    config.cache_enabled = False
    return config


@pytest.fixture
def sample_text_file(temp_dir):
    """Create a sample text file for testing."""
    file_path = temp_dir / "sample.txt"
    content = """
    This is a sample text file for testing.
    IP addresses: 192.168.1.1, 10.0.0.1, 172.16.254.1
    URLs: https://example.com, http://test.org, ftp://files.example.net
    Hashes: 
    MD5: 5d41402abc4b2a76b9719d911017c592
    SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
    SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    Email: test@example.com, admin@test.org
    """
    file_path.write_text(content)
    return file_path


@pytest.fixture
def mock_api_response():
    """Mock API response for testing."""
    return {
        "status": "success",
        "data": {
            "ip": "192.168.1.1",
            "country": "US",
            "region": "California",
            "city": "San Francisco"
        }
    }


@pytest.fixture
def mock_virustotal_response():
    """Mock VirusTotal API response."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 68,
                    "harmless": 2
                },
                "reputation": 0
            }
        }
    }


@pytest.fixture
def mock_shodan_response():
    """Mock Shodan API response."""
    return {
        "ip_str": "192.168.1.1",
        "org": "Test Organization",
        "data": [
            {
                "port": 80,
                "banner": "HTTP/1.1 200 OK",
                "product": "nginx"
            }
        ],
        "ports": [80, 443]
    }


@pytest.fixture
def cli_instance():
    """Provide a CLI instance for testing."""
    return TextManipulationCLI()


@pytest.fixture
def mock_input_handler():
    """Mock the input handler for CLI testing."""
    with patch('text_manipulation.cli.input_handler.InputHandler') as mock:
        yield mock


@pytest.fixture
def mock_display():
    """Mock the display handler for CLI testing."""
    with patch('text_manipulation.cli.display.Display') as mock:
        yield mock


@pytest.fixture
def mock_extractors():
    """Mock the extractors module."""
    with patch('text_manipulation.core.extractors') as mock:
        yield mock


@pytest.fixture
def mock_requests():
    """Mock requests library for API testing."""
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post:
        yield {"get": mock_get, "post": mock_post}


@pytest.fixture
def mock_aiohttp():
    """Mock aiohttp for async API testing."""
    with patch('aiohttp.ClientSession') as mock:
        yield mock


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables before each test."""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def sample_ips():
    """Provide sample IP addresses for testing."""
    return [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.254.1",
        "8.8.8.8",
        "1.1.1.1"
    ]


@pytest.fixture
def sample_urls():
    """Provide sample URLs for testing."""
    return [
        "https://example.com",
        "http://test.org",
        "ftp://files.example.net",
        "https://malicious-site.com",
        "http://192.168.1.1:8080"
    ]


@pytest.fixture
def sample_hashes():
    """Provide sample hashes for testing."""
    return {
        "md5": ["5d41402abc4b2a76b9719d911017c592", "098f6bcd4621d373cade4e832627b4f6"],
        "sha1": ["aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"],
        "sha256": ["2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"]
    }


@pytest.fixture
def mock_cache():
    """Mock the cache system."""
    with patch('text_manipulation.core.cache.Cache') as mock:
        mock_instance = MagicMock()
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_audit():
    """Mock the audit system."""
    with patch('text_manipulation.core.audit.AuditLogger') as mock:
        mock_instance = MagicMock()
        mock.return_value = mock_instance
        yield mock_instance 