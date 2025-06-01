"""
Configuration management for API keys and settings.

This module handles loading and managing API keys from environment variables
or a .env file for secure credential management.
"""

import os
from pathlib import Path
from typing import Optional
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
    
    def validate_api_keys(self) -> tuple[bool, list[str]]:
        """
        Validate that required API keys are present.
        
        Returns:
            Tuple of (all_keys_valid, list_of_missing_keys)
        """
        missing_keys = []
        
        if not self.virustotal_api_key:
            missing_keys.append('VIRUSTOTAL_API_KEY')
        
        if not self.abuseipdb_api_key:
            missing_keys.append('ABUSEIPDB_API_KEY')
        
        # IPInfo API key is optional (free tier available)
        # So we don't add it to missing_keys
        
        return len(missing_keys) == 0, missing_keys 