"""
Unit tests for the extractors module.
"""

import pytest
from unittest.mock import Mock, patch, mock_open
import re
from pathlib import Path

from text_manipulation.core.extractors import (
    extract_ips, extract_urls, extract_hashes, extract_emails,
    extract_from_file, extract_from_text, NetworkExtractor, FileExtractor
)


@pytest.mark.unit
@pytest.mark.core
class TestExtractors:
    """Test class for extractor functions."""

    def test_extract_ips_valid(self, sample_ips):
        """Test IP extraction with valid IP addresses."""
        text = "Found IPs: 192.168.1.1, 10.0.0.1, and 172.16.254.1"
        extracted = extract_ips(text)
        
        assert len(extracted) == 3
        assert "192.168.1.1" in extracted
        assert "10.0.0.1" in extracted
        assert "172.16.254.1" in extracted

    def test_extract_ips_invalid(self):
        """Test IP extraction with invalid IP addresses."""
        text = "Invalid IPs: 999.999.999.999, 256.1.1.1, not-an-ip"
        extracted = extract_ips(text)
        
        assert len(extracted) == 0

    def test_extract_urls_various_schemes(self, sample_urls):
        """Test URL extraction with different schemes."""
        text = "URLs: https://example.com, http://test.org, ftp://files.example.net"
        extracted = extract_urls(text)
        
        assert len(extracted) == 3
        assert "https://example.com" in extracted
        assert "http://test.org" in extracted
        assert "ftp://files.example.net" in extracted

    def test_extract_urls_excludes_executables(self):
        """Test that URL extraction doesn't capture executable files."""
        text = "Files: calc.exe, malware.exe, suspicious.bat, test.com, example.org"
        extracted = extract_urls(text)
        
        # Should not contain executables
        assert "calc.exe" not in extracted
        assert "malware.exe" not in extracted
        assert "suspicious.bat" not in extracted
        # Should contain proper domains/URLs
        assert "test.com" in extracted or "example.org" in extracted

    def test_extract_hashes_md5(self):
        """Test MD5 hash extraction."""
        text = "MD5: 5d41402abc4b2a76b9719d911017c592"
        extracted = extract_hashes(text, hash_type="md5")
        
        assert len(extracted) == 1
        assert "5d41402abc4b2a76b9719d911017c592" in extracted

    def test_extract_hashes_sha1(self):
        """Test SHA1 hash extraction."""
        text = "SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        extracted = extract_hashes(text, hash_type="sha1")
        
        assert len(extracted) == 1
        assert "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" in extracted

    def test_extract_hashes_sha256(self):
        """Test SHA256 hash extraction."""
        text = "SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        extracted = extract_hashes(text, hash_type="sha256")
        
        assert len(extracted) == 1
        assert "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae" in extracted

    def test_extract_emails(self):
        """Test email extraction."""
        text = "Contact: test@example.com, admin@test.org, invalid-email"
        extracted = extract_emails(text)
        
        assert len(extracted) >= 2
        assert "test@example.com" in extracted
        assert "admin@test.org" in extracted

    @patch("builtins.open", new_callable=mock_open, read_data="Sample file content with 192.168.1.1")
    def test_extract_from_file(self, mock_file):
        """Test extraction from file."""
        file_path = Path("test.txt")
        
        with patch('text_manipulation.core.extractors.extract_ips') as mock_extract:
            mock_extract.return_value = ["192.168.1.1"]
            
            result = extract_from_file(file_path, "ip")
            
            mock_extract.assert_called_once()
            assert result == ["192.168.1.1"]

    def test_extract_from_text_ip(self):
        """Test extraction from text for IP addresses."""
        text = "Server IP: 192.168.1.1"
        
        with patch('text_manipulation.core.extractors.extract_ips') as mock_extract:
            mock_extract.return_value = ["192.168.1.1"]
            
            result = extract_from_text(text, "ip")
            
            mock_extract.assert_called_once_with(text)
            assert result == ["192.168.1.1"]

    def test_extract_from_text_url(self):
        """Test extraction from text for URLs."""
        text = "Visit: https://example.com"
        
        with patch('text_manipulation.core.extractors.extract_urls') as mock_extract:
            mock_extract.return_value = ["https://example.com"]
            
            result = extract_from_text(text, "url")
            
            mock_extract.assert_called_once_with(text)
            assert result == ["https://example.com"]

    def test_extract_from_text_invalid_type(self):
        """Test extraction with invalid type."""
        text = "Some text"
        
        with pytest.raises(ValueError):
            extract_from_text(text, "invalid_type")

    def test_extract_ips_empty_text(self):
        """Test IP extraction with empty text."""
        extracted = extract_ips("")
        assert extracted == []

    def test_extract_urls_empty_text(self):
        """Test URL extraction with empty text."""
        extracted = extract_urls("")
        assert extracted == []

    def test_extract_hashes_empty_text(self):
        """Test hash extraction with empty text."""
        extracted = extract_hashes("", hash_type="md5")
        assert extracted == []

    def test_extract_emails_empty_text(self):
        """Test email extraction with empty text."""
        extracted = extract_emails("")
        assert extracted == []


@pytest.mark.unit
@pytest.mark.core
class TestMACAddressExtraction:
    """Test class for MAC address extraction improvements."""

    def test_mac_address_colon_format(self):
        """Test MAC address extraction with colon format."""
        text = "MAC addresses: 90:AB:CD:EF:12:34, 2b:a8:c3:d4:e5:f6"
        macs = NetworkExtractor.extract_mac_addresses(text)
        
        assert len(macs) >= 2
        assert "90:AB:CD:EF:12:34" in macs or "90:ab:cd:ef:12:34" in macs
        assert "2b:a8:c3:d4:e5:f6" in macs or "2B:A8:C3:D4:E5:F6" in macs

    def test_mac_address_dash_format(self):
        """Test MAC address extraction with dash format."""
        text = "Network interface: EE-FF-AA-BB-CC-DD"
        macs = NetworkExtractor.extract_mac_addresses(text)
        
        assert len(macs) >= 1
        assert "EE-FF-AA-BB-CC-DD" in macs or "ee-ff-aa-bb-cc-dd" in macs

    def test_mac_address_cisco_format(self):
        """Test MAC address extraction with Cisco format."""
        text = "Cisco device: 1234.5678.9ABC"
        macs = NetworkExtractor.extract_mac_addresses(text)
        
        assert len(macs) >= 1
        assert "1234.5678.9ABC" in macs or "1234.5678.9abc" in macs

    def test_mac_address_no_separators(self):
        """Test MAC address extraction without separators."""
        text = "Hardware ID: 001122334455"
        macs = NetworkExtractor.extract_mac_addresses(text)
        
        assert len(macs) >= 1
        assert "001122334455" in macs

    def test_mac_address_partial(self):
        """Test partial MAC address extraction."""
        text = "Partial MACs: 90:AB, 34:56, EE-FF"
        macs = NetworkExtractor.extract_mac_addresses(text)
        
        assert len(macs) >= 3
        # Should capture partial MAC addresses
        assert any("90:AB" in mac.upper() for mac in macs)
        assert any("34:56" in mac.upper() for mac in macs)
        assert any("EE-FF" in mac.upper() for mac in macs)

    def test_mac_address_mixed_test_data(self):
        """Test with the actual problematic MAC data from the issue."""
        mac_data = """90:AB
90:ab
EE-FF
3A:B7
2b:a8
ae:61
34:56
56:78
2233.
ab:cd
E5:F6
34:e6
90:f3
ef:12
ce:11
001122334455
44:55"""
        
        macs = NetworkExtractor.extract_mac_addresses(mac_data)
        
        # Should capture most or all of these MAC addresses
        assert len(macs) >= 15
        assert "90:AB" in macs or "90:ab" in macs
        assert "EE-FF" in macs or "ee-ff" in macs
        assert "001122334455" in macs


@pytest.mark.unit
@pytest.mark.core
class TestURLExecutableSeparation:
    """Test class for URL vs executable separation."""

    def test_url_vs_executable_separation(self):
        """Test that URLs and executables are properly separated."""
        test_data = """suspicious.deb
test-site.co.uk
calc.exe
example.com
server.company.com
wallet.dat
api.virustotal.com
files.example.org
evil-c2.badguys.com
host.example.com
company.org
malware.exe
malicious.sh
rundll32.exe
powershell.exe
malicious-domain.evil
malicious-site.evil
www.google.com
google.com
suspicious.bat
sub.domain.example.org
sub.domain.co.uk
exploit.bin
test.user
payload.exe
evil.scr
www.example.com"""

        # Test URL extraction
        urls = NetworkExtractor.extract_urls(test_data)
        
        # URLs should NOT contain executables
        assert "calc.exe" not in urls
        assert "malware.exe" not in urls
        assert "powershell.exe" not in urls
        assert "suspicious.bat" not in urls
        assert "evil.scr" not in urls
        
        # Test executable extraction
        executables = FileExtractor.extract_executables(test_data)
        
        # Executables should contain proper executable files
        assert "calc.exe" in executables
        assert "malware.exe" in executables
        assert "powershell.exe" in executables
        assert "suspicious.bat" in executables
        assert "evil.scr" in executables
        
        # Executables should NOT contain domains
        assert "example.com" not in executables
        assert "google.com" not in executables
        assert "api.virustotal.com" not in executables

    def test_domain_extraction_excludes_executables(self):
        """Test that domain extraction excludes executable file extensions."""
        test_data = """api.virustotal.com
calc.exe
example.com
malware.exe
test-site.co.uk
suspicious.bat
files.example.org"""

        domains = NetworkExtractor.extract_domains(test_data)
        
        # Should contain domains
        assert "api.virustotal.com" in domains
        assert "example.com" in domains
        assert "test-site.co.uk" in domains
        assert "files.example.org" in domains
        
        # Should NOT contain executables
        assert "calc.exe" not in domains
        assert "malware.exe" not in domains
        assert "suspicious.bat" not in domains

    def test_executable_extraction_excludes_domains(self):
        """Test that executable extraction excludes known domain patterns."""
        test_data = """calc.exe
example.com
malware.exe
api.virustotal.com
suspicious.bat
test-site.co.uk
payload.exe"""

        executables = FileExtractor.extract_executables(test_data)
        
        # Should contain executables
        assert "calc.exe" in executables
        assert "malware.exe" in executables
        assert "suspicious.bat" in executables
        assert "payload.exe" in executables
        
        # Should NOT contain domains
        assert "example.com" not in executables
        assert "api.virustotal.com" not in executables
        assert "test-site.co.uk" not in executables


@pytest.mark.unit
@pytest.mark.core
class TestPatternMatchingEdgeCases:
    """Test class for edge cases in pattern matching."""

    def test_file_vs_domain_ambiguity(self):
        """Test handling of ambiguous patterns that could be files or domains."""
        test_data = """wallet.dat
test.user
config.ini
data.log
readme.txt
example.com
test.org"""

        # Domain extraction should exclude file extensions
        domains = NetworkExtractor.extract_domains(test_data)
        assert "wallet.dat" not in domains
        assert "test.user" not in domains  # .user is not a valid TLD
        assert "config.ini" not in domains
        assert "example.com" in domains
        assert "test.org" in domains

    def test_partial_mac_vs_ports(self):
        """Test that partial MAC addresses don't interfere with port numbers."""
        test_data = """MAC: 34:56
Port: 80:443
Interface: ab:cd
Service: 22:22"""

        macs = NetworkExtractor.extract_mac_addresses(test_data)
        
        # Should capture partial MACs but not port-like patterns
        assert any("34:56" in mac for mac in macs)
        assert any("ab:cd" in mac.lower() for mac in macs)
        # Port patterns should not be captured as MACs
        assert "80:443" not in macs
        assert "22:22" not in macs

    def test_hash_vs_mac_disambiguation(self):
        """Test that hashes and MAC addresses don't interfere with each other."""
        test_data = """MAC: 001122334455
Hash: 5d41402abc4b2a76b9719d911017c592
Another MAC: 12:34:56:78:9A:BC"""

        macs = NetworkExtractor.extract_mac_addresses(test_data)
        hashes = extract_hashes(test_data, "md5")
        
        # MAC should be captured
        assert "001122334455" in macs
        assert any("12:34:56:78:9A:BC" in mac.upper() for mac in macs)
        
        # Hash should be captured separately
        assert "5d41402abc4b2a76b9719d911017c592" in hashes
        
        # No overlap
        assert "5d41402abc4b2a76b9719d911017c592" not in macs
        assert "001122334455" not in hashes 