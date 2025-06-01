"""
VirusTotal API client for IP address reputation checking.

This module provides a clean interface to the VirusTotal API v3
for checking IP address reputation and threat intelligence.
"""

import asyncio
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