"""
VirusTotal API client for IP address, hash, and URL reputation checking.

This module provides a clean interface to the VirusTotal API v3
for checking IP addresses, file hashes, and URL reputation and threat intelligence.
"""

import asyncio
import base64
from typing import Dict, Any, Optional
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential


class VirusTotalClient:
    """Client for interacting with VirusTotal API v3."""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        """
        Initialize VirusTotal client with API key.
        
        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address reputation on VirusTotal.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary containing IP reputation data
        """
        url = f"{self.BASE_URL}/ip_addresses/{ip_address}"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_ip_report(data)
                    elif response.status == 404:
                        return {"ip": ip_address, "error": "IP not found", "status": "unknown"}
                    else:
                        return {"ip": ip_address, "error": f"API error: {response.status}"}
                        
            except asyncio.TimeoutError:
                return {"ip": ip_address, "error": "Request timeout"}
            except Exception as e:
                return {"ip": ip_address, "error": str(e)}

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def check_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash reputation on VirusTotal.
        
        Args:
            file_hash: File hash (MD5, SHA1, SHA256) to check
            
        Returns:
            Dictionary containing hash reputation data
        """
        url = f"{self.BASE_URL}/files/{file_hash}"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_hash_report(data)
                    elif response.status == 404:
                        return {"hash": file_hash, "error": "Hash not found", "status": "unknown"}
                    else:
                        return {"hash": file_hash, "error": f"API error: {response.status}"}
                        
            except asyncio.TimeoutError:
                return {"hash": file_hash, "error": "Request timeout"}
            except Exception as e:
                return {"hash": file_hash, "error": str(e)}

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def check_url_reputation(self, url_to_check: str) -> Dict[str, Any]:
        """
        Check URL reputation on VirusTotal.
        
        Args:
            url_to_check: URL to check for reputation
            
        Returns:
            Dictionary containing URL reputation data
        """
        # VirusTotal uses base64 encoding without padding for URL IDs
        url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().rstrip('=')
        api_url = f"{self.BASE_URL}/urls/{url_id}"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(api_url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_url_report(data, url_to_check)
                    elif response.status == 404:
                        return {"url": url_to_check, "error": "URL not found", "status": "unknown"}
                    else:
                        return {"url": url_to_check, "error": f"API error: {response.status}"}
                        
            except asyncio.TimeoutError:
                return {"url": url_to_check, "error": "Request timeout"}
            except Exception as e:
                return {"url": url_to_check, "error": str(e)}
    
    def _parse_ip_report(self, api_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse VirusTotal API response into structured report.
        
        Args:
            api_response: Raw API response
            
        Returns:
            Parsed IP reputation report
        """
        data = api_response.get("data", {})
        attributes = data.get("attributes", {})
        
        # Extract reputation scores
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        return {
            "ip": data.get("id", ""),
            "country": attributes.get("country", "Unknown"),
            "owner": attributes.get("as_owner", "Unknown"),
            "reputation_stats": {
                "harmless": last_analysis_stats.get("harmless", 0),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
            },
            "reputation_score": self._calculate_reputation_score(last_analysis_stats),
            "last_analysis_date": attributes.get("last_analysis_date", "N/A")
        }

    def _parse_hash_report(self, api_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse VirusTotal hash analysis response into structured report.
        
        Args:
            api_response: Raw API response
            
        Returns:
            Parsed hash reputation report
        """
        data = api_response.get("data", {})
        attributes = data.get("attributes", {})
        
        # Extract analysis statistics
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        # Extract file names
        names = attributes.get("names", [])
        meaningful_name = attributes.get("meaningful_name", "")
        
        return {
            "hash": data.get("id", ""),
            "file_type": attributes.get("type_description", "Unknown"),
            "file_size": attributes.get("size", 0),
            "names": names[:5] if names else [],  # Limit to first 5 names
            "meaningful_name": meaningful_name,
            "first_submission_date": attributes.get("first_submission_date", "N/A"),
            "last_analysis_date": attributes.get("last_analysis_date", "N/A"),
            "reputation_stats": {
                "harmless": last_analysis_stats.get("harmless", 0),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
            },
            "reputation_score": self._calculate_reputation_score(last_analysis_stats),
            "magic": attributes.get("magic", "Unknown")
        }

    def _parse_url_report(self, api_response: Dict[str, Any], original_url: str) -> Dict[str, Any]:
        """
        Parse VirusTotal URL analysis response into structured report.
        
        Args:
            api_response: Raw API response
            original_url: Original URL that was analyzed
            
        Returns:
            Parsed URL reputation report
        """
        data = api_response.get("data", {})
        attributes = data.get("attributes", {})
        
        # Extract analysis statistics
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        return {
            "url": original_url,
            "final_url": attributes.get("url", original_url),
            "title": attributes.get("title", "Unknown"),
            "last_analysis_date": attributes.get("last_analysis_date", "N/A"),
            "first_submission_date": attributes.get("first_submission_date", "N/A"),
            "reputation_stats": {
                "harmless": last_analysis_stats.get("harmless", 0),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
            },
            "reputation_score": self._calculate_reputation_score(last_analysis_stats),
            "categories": attributes.get("categories", {}),
            "threat_names": attributes.get("threat_names", [])
        }
    
    def _calculate_reputation_score(self, stats: Dict[str, int]) -> str:
        """
        Calculate overall reputation score from analysis stats.
        
        Args:
            stats: Dictionary of detection statistics
            
        Returns:
            Reputation score (Clean, Suspicious, Malicious)
        """
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        if malicious > 0:
            return "Malicious"
        elif suspicious > 0:
            return "Suspicious"
        else:
            return "Clean" 