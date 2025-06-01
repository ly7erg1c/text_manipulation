"""
AbuseIPDB API client for IP address abuse checking.

This module provides a clean interface to the AbuseIPDB API v2
for checking IP addresses against abuse reports.
"""

import asyncio
from typing import Dict, Any, List
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential


class AbuseIPDBClient:
    """Client for interacting with AbuseIPDB API v2."""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str):
        """
        Initialize AbuseIPDB client with API key.
        
        Args:
            api_key: AbuseIPDB API key
        """
        self.api_key = api_key
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def check_ip_abuse(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address for abuse reports on AbuseIPDB.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary containing IP abuse data
        """
        url = f"{self.BASE_URL}/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": "90",  # Check last 90 days - string format
            "verbose": ""  # Empty string enables verbose mode
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    url, 
                    headers=self.headers, 
                    params=params
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_abuse_report(data)
                    else:
                        return {"ip": ip_address, "error": f"API error: {response.status}"}
                        
            except asyncio.TimeoutError:
                return {"ip": ip_address, "error": "Request timeout"}
            except Exception as e:
                return {"ip": ip_address, "error": str(e)}
    
    def _parse_abuse_report(self, api_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse AbuseIPDB API response into structured report.
        
        Args:
            api_response: Raw API response
            
        Returns:
            Parsed abuse report
        """
        data = api_response.get("data", {})
        
        return {
            "ip": data.get("ipAddress", ""),
            "country_code": data.get("countryCode", "Unknown"),
            "usage_type": data.get("usageType", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt", "Never"),
            "is_whitelisted": data.get("isWhitelisted", False),
            "abuse_categories": self._get_abuse_categories(data.get("reports", []))
        }
    
    def _get_abuse_categories(self, reports: List[Dict[str, Any]]) -> List[str]:
        """
        Extract unique abuse categories from reports.
        
        Args:
            reports: List of abuse reports
            
        Returns:
            List of unique abuse categories
        """
        categories = set()
        category_mapping = {
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }
        
        for report in reports[:5]:  # Limit to first 5 reports
            for cat_id in report.get("categories", []):
                if cat_id in category_mapping:
                    categories.add(category_mapping[cat_id])
        
        return sorted(list(categories)) 