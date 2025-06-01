"""
Configuration management for API keys and settings.

This module handles loading and managing API keys from environment variables
or a .env file for secure credential management.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
from dotenv import load_dotenv


class APIConfig:
    """Manages API configuration and credentials."""
    
    def __init__(self):
        """Initialize API configuration by loading environment variables."""
        self._load_environment()
        
    def _load_environment(self) -> None:
        """Load environment variables from .env file if it exists."""
        env_path = Path('.env')
        if env_path.exists():
            load_dotenv(env_path)
    
    @property
    def virustotal_api_key(self) -> Optional[str]:
        """Get VirusTotal API key from environment."""
        return os.getenv('VIRUSTOTAL_API_KEY')
    
    @property
    def abuseipdb_api_key(self) -> Optional[str]:
        """Get AbuseIPDB API key from environment."""
        return os.getenv('ABUSEIPDB_API_KEY')
    
    @property
    def ipinfo_api_key(self) -> Optional[str]:
        """Get IPInfo API key from environment."""
        return os.getenv('IPINFO_API_KEY')
    
    @property
    def shodan_api_key(self) -> Optional[str]:
        """Get Shodan API key from environment."""
        return os.getenv('SHODAN_API_KEY')
    
    @property
    def whois_api_key(self) -> Optional[str]:
        """Get WHOIS API key from environment."""
        return os.getenv('WHOIS_API_KEY')
    
    @property
    def threatfox_api_key(self) -> Optional[str]:
        """Get ThreatFox API key from environment."""
        return os.getenv('THREATFOX_API_KEY')
    
    @property
    def passivedns_api_key(self) -> Optional[str]:
        """Get Passive DNS API key from environment."""
        return os.getenv('PASSIVEDNS_API_KEY')
    
    @property
    def hybrid_analysis_api_key(self) -> Optional[str]:
        """Get Hybrid Analysis API key from environment."""
        return os.getenv('HYBRID_ANALYSIS_API_KEY')
    
    @property
    def otx_api_key(self) -> Optional[str]:
        """Get AlienVault OTX API key from environment."""
        return os.getenv('OTX_API_KEY')
    
    @property
    def cache_enabled(self) -> bool:
        """Check if caching is enabled."""
        return os.getenv('CACHE_ENABLED', 'true').lower() in ('true', '1', 'yes', 'on')
    
    @property
    def cache_ttl(self) -> int:
        """Get cache TTL in seconds."""
        return int(os.getenv('CACHE_TTL', '3600'))  # Default 1 hour
    
    @property
    def audit_enabled(self) -> bool:
        """Check if audit logging is enabled."""
        return os.getenv('AUDIT_ENABLED', 'true').lower() in ('true', '1', 'yes', 'on')
    
    @property
    def max_archive_size_mb(self) -> int:
        """Get maximum archive size to process in MB."""
        return int(os.getenv('MAX_ARCHIVE_SIZE_MB', '50'))
    
    @property
    def max_files_per_archive(self) -> int:
        """Get maximum number of files to extract from each archive."""
        return int(os.getenv('MAX_FILES_PER_ARCHIVE', '100'))
    
    def get_api_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of all API configurations.
        
        Returns:
            Dictionary with API status information
        """
        api_configs = {
            'VirusTotal': {
                'key_set': bool(self.virustotal_api_key),
                'required': True,
                'description': 'Hash and URL analysis'
            },
            'AbuseIPDB': {
                'key_set': bool(self.abuseipdb_api_key),
                'required': False,
                'description': 'IP reputation analysis'
            },
            'IPInfo': {
                'key_set': bool(self.ipinfo_api_key),
                'required': False,
                'description': 'IP geolocation and ASN information'
            },
            'Shodan': {
                'key_set': bool(self.shodan_api_key),
                'required': False,
                'description': 'Device and service information'
            },
            'WHOIS': {
                'key_set': bool(self.whois_api_key),
                'required': False,
                'description': 'Domain and IP registration data'
            },
            'ThreatFox': {
                'key_set': bool(self.threatfox_api_key),
                'required': False,
                'description': 'IOC database queries'
            },
            'Passive DNS': {
                'key_set': bool(self.passivedns_api_key),
                'required': False,
                'description': 'Historical DNS resolution data'
            },
            'Hybrid Analysis': {
                'key_set': bool(self.hybrid_analysis_api_key),
                'required': False,
                'description': 'Malware sandbox analysis'
            },
            'AlienVault OTX': {
                'key_set': bool(self.otx_api_key),
                'required': False,
                'description': 'Open threat exchange data'
            }
        }
        
        return api_configs
    
    def validate_api_keys(self) -> tuple[bool, list[str]]:
        """
        Validate that required API keys are present.
        
        Returns:
            Tuple of (all_keys_valid, list_of_missing_keys)
        """
        missing_keys = []
        
        # Only VirusTotal is considered required for core functionality
        if not self.virustotal_api_key:
            missing_keys.append('VIRUSTOTAL_API_KEY')
        
        # All other API keys are optional and provide enhanced functionality
        
        return len(missing_keys) == 0, missing_keys
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current configuration.
        
        Returns:
            Dictionary with configuration summary
        """
        api_status = self.get_api_status()
        configured_apis = sum(1 for api in api_status.values() if api['key_set'])
        total_apis = len(api_status)
        
        return {
            'apis_configured': f"{configured_apis}/{total_apis}",
            'cache_enabled': self.cache_enabled,
            'cache_ttl_hours': self.cache_ttl / 3600,
            'audit_enabled': self.audit_enabled,
            'max_archive_size_mb': self.max_archive_size_mb,
            'max_files_per_archive': self.max_files_per_archive,
            'api_status': api_status
        }
    
    def set_api_key(self, service: str, api_key: str) -> bool:
        """
        Set an API key in the environment (for the current session).
        
        Args:
            service: Service name (e.g., 'virustotal', 'shodan')
            api_key: API key value
            
        Returns:
            True if successful
        """
        service_map = {
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'abuseipdb': 'ABUSEIPDB_API_KEY',
            'ipinfo': 'IPINFO_API_KEY',
            'shodan': 'SHODAN_API_KEY',
            'whois': 'WHOIS_API_KEY',
            'threatfox': 'THREATFOX_API_KEY',
            'passivedns': 'PASSIVEDNS_API_KEY',
            'hybrid_analysis': 'HYBRID_ANALYSIS_API_KEY',
            'otx': 'OTX_API_KEY'
        }
        
        env_var = service_map.get(service.lower())
        if env_var:
            os.environ[env_var] = api_key
            return True
        
        return False
    
    def clear_api_key(self, service: str) -> bool:
        """
        Clear an API key from the environment.
        
        Args:
            service: Service name
            
        Returns:
            True if successful
        """
        service_map = {
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'abuseipdb': 'ABUSEIPDB_API_KEY',
            'ipinfo': 'IPINFO_API_KEY',
            'shodan': 'SHODAN_API_KEY',
            'whois': 'WHOIS_API_KEY',
            'threatfox': 'THREATFOX_API_KEY',
            'passivedns': 'PASSIVEDNS_API_KEY',
            'hybrid_analysis': 'HYBRID_ANALYSIS_API_KEY',
            'otx': 'OTX_API_KEY'
        }
        
        env_var = service_map.get(service.lower())
        if env_var and env_var in os.environ:
            del os.environ[env_var]
            return True
        
        return False 