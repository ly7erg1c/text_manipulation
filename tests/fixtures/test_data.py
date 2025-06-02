"""
Test data fixtures and sample data for tests.
"""

# Sample IP addresses for testing
SAMPLE_IPS = [
    "192.168.1.1",
    "10.0.0.1", 
    "172.16.254.1",
    "8.8.8.8",
    "1.1.1.1",
    "208.67.222.222",
    "127.0.0.1"
]

# Invalid IP addresses for negative testing
INVALID_IPS = [
    "999.999.999.999",
    "256.1.1.1",
    "192.168.1",
    "not-an-ip",
    "192.168.1.1.1",
    "300.300.300.300"
]

# Sample URLs for testing
SAMPLE_URLS = [
    "https://example.com",
    "http://test.org",
    "ftp://files.example.net",
    "https://malicious-site.com/payload",
    "http://192.168.1.1:8080",
    "https://api.service.com/v1/data",
    "mailto:test@example.com"
]

# Sample hashes for testing
SAMPLE_HASHES = {
    "md5": [
        "5d41402abc4b2a76b9719d911017c592",
        "098f6bcd4621d373cade4e832627b4f6",
        "d41d8cd98f00b204e9800998ecf8427e"
    ],
    "sha1": [
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    ],
    "sha256": [
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
    ]
}

# Sample email addresses
SAMPLE_EMAILS = [
    "test@example.com",
    "admin@test.org",
    "security@company.net",
    "alerts@monitoring.gov",
    "user+tag@domain.co.uk"
]

# Sample text content with mixed data types
MIXED_CONTENT_SAMPLE = """
Security Analysis Report - 2024
===============================

Network Infrastructure:
- Gateway: 192.168.1.1 (internal)
- DNS Servers: 8.8.8.8, 1.1.1.1 (external)
- Web Server: 10.0.0.100:80

Suspicious URLs Detected:
1. https://malicious-domain.com/backdoor
2. http://phishing-site.org/login
3. ftp://suspicious-server.net/files

File Analysis Results:
- Config.exe: MD5 5d41402abc4b2a76b9719d911017c592
- System.dll: SHA1 aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
- Update.bin: SHA256 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae

Contact Information:
- SOC Team: soc@company.com
- Incident Response: ir@security.org
- External Vendor: support@vendor.net

Additional IoCs:
- 172.16.254.1 (compromised host)
- https://c2-server.evil.com/beacon
- report.pdf: 098f6bcd4621d373cade4e832627b4f6
"""

# API Response Mock Data
VIRUSTOTAL_IP_RESPONSE = {
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
            "country": "US",
            "network": "192.168.0.0/16"
        }
    }
}

VIRUSTOTAL_HASH_RESPONSE = {
    "data": {
        "id": "5d41402abc4b2a76b9719d911017c592",
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "harmless": 0,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 74,
                "timeout": 0
            },
            "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            "names": ["test_file.txt"]
        }
    }
}

SHODAN_IP_RESPONSE = {
    "ip_str": "192.168.1.1",
    "org": "Test Organization",
    "data": [
        {
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
            "product": "nginx",
            "version": "1.18.0"
        },
        {
            "port": 443,
            "banner": "TLS/SSL Certificate",
            "product": "OpenSSL",
            "ssl": {
                "cert": {
                    "subject": {
                        "CN": "example.com"
                    }
                }
            }
        }
    ],
    "ports": [80, 443],
    "vulns": {},
    "tags": ["web-server"]
}

# Error response examples
ERROR_RESPONSES = {
    "not_found": {
        "error": {
            "code": "NotFound",
            "message": "The requested resource was not found"
        }
    },
    "rate_limit": {
        "error": {
            "code": "QuotaExceeded", 
            "message": "Request rate limit exceeded"
        }
    },
    "invalid_api_key": {
        "error": {
            "code": "AuthenticationRequiredError",
            "message": "Valid API key required"
        }
    }
}

# Configuration test data
TEST_CONFIG = {
    "debug": True,
    "cache_enabled": False,
    "api_timeout": 30,
    "max_retries": 3,
    "rate_limit_delay": 1.0,
    "output_format": "json"
}

# Archive test data (for archive processor tests)
ARCHIVE_TEST_FILES = {
    "sample.zip": {
        "files": [
            "readme.txt",
            "data/info.csv", 
            "logs/system.log"
        ],
        "password": None
    },
    "protected.rar": {
        "files": [
            "secret.txt",
            "config.ini"
        ],
        "password": "test123"
    }
}

# Performance test data
LARGE_TEXT_SAMPLE = MIXED_CONTENT_SAMPLE * 1000  # Repeat 1000 times for performance tests 