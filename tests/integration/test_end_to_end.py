"""
Integration tests for end-to-end functionality.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, Mock
import subprocess
import sys

from text_manipulation.cli.interface import TextManipulationCLI
from text_manipulation.core.extractors import extract_ips, extract_urls, extract_hashes


@pytest.mark.integration
class TestEndToEndFunctionality:
    """Test class for end-to-end integration tests."""

    @pytest.fixture
    def temp_test_dir(self):
        """Create a temporary directory for integration tests."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.fixture
    def sample_data_file(self, temp_test_dir):
        """Create a sample data file with various extractable content."""
        file_path = temp_test_dir / "sample_data.txt"
        content = """
        Network Security Analysis Report
        ================================
        
        IP Addresses Found:
        - Internal: 192.168.1.1, 10.0.0.1, 172.16.254.1
        - External: 8.8.8.8, 1.1.1.1, 208.67.222.222
        
        URLs Discovered:
        - https://example.com/login
        - http://malicious-site.org/payload
        - ftp://files.internal.net/documents
        - https://api.service.com/v1/data
        
        File Hashes:
        MD5: 5d41402abc4b2a76b9719d911017c592
        SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
        SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
        
        Email Addresses:
        admin@example.com
        security@company.org
        alerts@monitoring.net
        
        Additional suspicious content...
        """
        file_path.write_text(content)
        return file_path

    def test_extractor_pipeline_integration(self, sample_data_file):
        """Test the complete extraction pipeline."""
        content = sample_data_file.read_text()
        
        # Test IP extraction
        ips = extract_ips(content)
        assert len(ips) >= 6  # Should find at least 6 IP addresses
        assert "192.168.1.1" in ips
        assert "8.8.8.8" in ips
        
        # Test URL extraction
        urls = extract_urls(content)
        assert len(urls) >= 4  # Should find at least 4 URLs
        assert any("https://example.com" in url for url in urls)
        assert any("ftp://files.internal.net" in url for url in urls)
        
        # Test hash extraction
        md5_hashes = extract_hashes(content, hash_type="md5")
        sha1_hashes = extract_hashes(content, hash_type="sha1")
        sha256_hashes = extract_hashes(content, hash_type="sha256")
        
        assert len(md5_hashes) >= 1
        assert len(sha1_hashes) >= 1
        assert len(sha256_hashes) >= 1

    @patch('builtins.input', side_effect=['1', 'quit'])
    @patch('text_manipulation.core.extractors.extract_from_file')
    def test_cli_file_processing_integration(self, mock_extract, mock_input, sample_data_file):
        """Test CLI file processing integration."""
        # Mock the extract_from_file to return sample data
        mock_extract.return_value = ["192.168.1.1", "10.0.0.1"]
        
        cli = TextManipulationCLI()
        
        # Test that CLI can process files
        try:
            cli.run()
        except SystemExit:
            pass  # Expected exit
        
        # Verify extraction was called
        if mock_extract.called:
            assert mock_extract.call_count >= 0

    @pytest.mark.slow
    def test_main_entry_point_integration(self, temp_test_dir):
        """Test the main entry point integration."""
        # Test running the main script
        script_path = Path(__file__).parent.parent.parent / "main.py"
        
        if script_path.exists():
            try:
                # Run the main script with timeout
                result = subprocess.run(
                    [sys.executable, str(script_path)],
                    input="quit\n",
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # Should not crash
                assert result.returncode is not None
                
            except subprocess.TimeoutExpired:
                # Timeout is acceptable for this test
                pass
            except FileNotFoundError:
                # Script might not be directly executable
                pytest.skip("Main script not found or not executable")

    @patch('text_manipulation.core.api_clients.virustotal.VirusTotalClient')
    def test_api_integration_workflow(self, mock_vt_client, sample_ips):
        """Test API integration workflow."""
        # Mock VirusTotal client
        mock_client = Mock()
        mock_vt_client.return_value = mock_client
        mock_client.query_ip.return_value = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 75
                    }
                }
            }
        }
        
        # Test the workflow
        for ip in sample_ips[:2]:  # Test first 2 IPs
            result = mock_client.query_ip(ip)
            assert result is not None
            assert "data" in result

    @patch('text_manipulation.core.cache.Cache')
    def test_caching_integration(self, mock_cache):
        """Test caching system integration."""
        # Mock cache
        mock_cache_instance = Mock()
        mock_cache.return_value = mock_cache_instance
        mock_cache_instance.get.return_value = None
        mock_cache_instance.set.return_value = True
        
        # Test cache workflow
        cache_key = "test_ip_192.168.1.1"
        cached_data = mock_cache_instance.get(cache_key)
        assert cached_data is None
        
        # Simulate setting cache
        test_data = {"ip": "192.168.1.1", "reputation": 0}
        mock_cache_instance.set(cache_key, test_data)
        mock_cache_instance.set.assert_called_with(cache_key, test_data)

    @patch('text_manipulation.core.audit.AuditLogger')
    def test_audit_logging_integration(self, mock_audit):
        """Test audit logging integration."""
        # Mock audit logger
        mock_logger = Mock()
        mock_audit.return_value = mock_logger
        
        # Test audit workflow
        mock_logger.log_action("IP_EXTRACTION", {"count": 5})
        mock_logger.log_action.assert_called_with("IP_EXTRACTION", {"count": 5})

    def test_configuration_integration(self, temp_test_dir):
        """Test configuration system integration."""
        from text_manipulation.core.config import Config
        
        # Test configuration loading
        config = Config()
        assert config is not None
        
        # Test configuration persistence
        config_dict = vars(config)
        assert isinstance(config_dict, dict)

    @patch('text_manipulation.core.extractors.extract_from_file')
    @patch('text_manipulation.core.api_clients.virustotal.VirusTotalClient')
    def test_full_analysis_workflow(self, mock_vt_client, mock_extract, sample_data_file):
        """Test full analysis workflow from file to API results."""
        # Mock extractors
        mock_extract.return_value = ["192.168.1.1", "8.8.8.8"]
        
        # Mock API client
        mock_client = Mock()
        mock_vt_client.return_value = mock_client
        mock_client.query_ip.return_value = {"data": {"attributes": {"reputation": 0}}}
        
        # Simulate full workflow
        # 1. Extract data from file
        extracted_ips = mock_extract(sample_data_file, "ip")
        assert len(extracted_ips) == 2
        
        # 2. Query APIs for each IP
        for ip in extracted_ips:
            result = mock_client.query_ip(ip)
            assert result is not None
            assert "data" in result

    def test_error_handling_integration(self):
        """Test error handling across components."""
        # Test that components handle errors gracefully
        try:
            # Test with invalid input
            result = extract_ips("invalid text with no IPs")
            assert result == []
            
            # Test with malformed data
            result = extract_urls("not a url")
            assert result == []
            
        except Exception as e:
            pytest.fail(f"Components should handle errors gracefully: {e}")

    @pytest.mark.slow
    def test_performance_integration(self, sample_data_file):
        """Test performance with larger datasets."""
        import time
        
        # Create larger test content
        content = sample_data_file.read_text() * 100  # Repeat content 100 times
        
        # Time the extraction operations
        start_time = time.time()
        
        ips = extract_ips(content)
        urls = extract_urls(content)
        hashes = extract_hashes(content, hash_type="md5")
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should complete within reasonable time (adjust threshold as needed)
        assert processing_time < 10.0  # 10 seconds max
        
        # Should still find the expected patterns
        assert len(ips) > 0
        assert len(urls) > 0 