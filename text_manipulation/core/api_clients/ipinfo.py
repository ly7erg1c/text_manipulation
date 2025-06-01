"""
IPInfo API client for IP address geolocation and details.

This module provides a clean interface to the IPInfo API
for retrieving geolocation and network information about IP addresses.
"""

import asyncio
from typing import Dict, Any, Optional
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential


class IPInfoClient:
    """Client for interacting with IPInfo API."""
    
    BASE_URL = "https://ipinfo.io"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize IPInfo client with optional API key.
        
        Args:
            api_key: IPInfo API key (optional, can use free tier without key)
        """
        self.api_key = api_key
        self.headers = {"Accept": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=8)
    )
    async def get_ip_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Get comprehensive information about an IP address.
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            Dictionary containing IP geolocation and network data
        """
        url = f"{self.BASE_URL}/{ip_address}/json"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_ip_info(data)
                    elif response.status == 429:
                        return {"ip": ip_address, "error": "Rate limit exceeded", "status": "rate_limited"}
                    elif response.status == 404:
                        return {"ip": ip_address, "error": "IP not found", "status": "not_found"}
                    else:
                        return {"ip": ip_address, "error": f"API error: {response.status}"}
                        
            except asyncio.TimeoutError:
                return {"ip": ip_address, "error": "Request timeout"}
            except Exception as e:
                return {"ip": ip_address, "error": str(e)}
    
    def _parse_ip_info(self, api_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse IPInfo API response into structured report.
        
        Args:
            api_response: Raw API response from IPInfo
            
        Returns:
            Parsed IP information report
        """
        # Extract location data
        location = api_response.get("loc", "").split(",")
        latitude = location[0] if len(location) > 0 else None
        longitude = location[1] if len(location) > 1 else None
        
        return {
            "ip": api_response.get("ip", ""),
            "hostname": api_response.get("hostname", "N/A"),
            "city": api_response.get("city", "Unknown"),
            "region": api_response.get("region", "Unknown"),
            "country": api_response.get("country", "Unknown"),
            "country_name": self._get_country_name(api_response.get("country", "")),
            "latitude": float(latitude) if latitude else None,
            "longitude": float(longitude) if longitude else None,
            "postal_code": api_response.get("postal", "N/A"),
            "timezone": api_response.get("timezone", "N/A"),
            "organization": api_response.get("org", "Unknown"),
            "asn": self._extract_asn(api_response.get("org", "")),
            "is_mobile": api_response.get("mobile", False),
            "is_vpn": api_response.get("vpn", False),
            "is_proxy": api_response.get("proxy", False),
            "is_hosting": api_response.get("hosting", False)
        }
    
    def _extract_asn(self, org_string: str) -> Optional[str]:
        """
        Extract ASN from organization string.
        
        Args:
            org_string: Organization string that may contain ASN
            
        Returns:
            ASN number if found, None otherwise
        """
        if not org_string:
            return None
            
        # ASN typically appears as "AS12345" at the beginning
        parts = org_string.split()
        if parts and parts[0].startswith("AS"):
            return parts[0]
        return None
    
    def _get_country_name(self, country_code: str) -> str:
        """
        Get full country name from country code.
        
        Args:
            country_code: Two-letter country code
            
        Returns:
            Full country name or the code if not found
        """
        country_names = {
            "US": "United States",
            "CA": "Canada",
            "GB": "United Kingdom",
            "DE": "Germany",
            "FR": "France",
            "JP": "Japan",
            "CN": "China",
            "RU": "Russia",
            "IN": "India",
            "BR": "Brazil",
            "AU": "Australia",
            "NL": "Netherlands",
            "SE": "Sweden",
            "NO": "Norway",
            "DK": "Denmark",
            "FI": "Finland",
            "IT": "Italy",
            "ES": "Spain",
            "CH": "Switzerland",
            "AT": "Austria",
            "BE": "Belgium",
            "PL": "Poland",
            "CZ": "Czech Republic",
            "HU": "Hungary",
            "RO": "Romania",
            "GR": "Greece",
            "PT": "Portugal",
            "IE": "Ireland",
            "KR": "South Korea",
            "TW": "Taiwan",
            "HK": "Hong Kong",
            "SG": "Singapore",
            "MY": "Malaysia",
            "TH": "Thailand",
            "ID": "Indonesia",
            "PH": "Philippines",
            "VN": "Vietnam",
            "ZA": "South Africa",
            "EG": "Egypt",
            "NG": "Nigeria",
            "KE": "Kenya",
            "MX": "Mexico",
            "AR": "Argentina",
            "CL": "Chile",
            "CO": "Colombia",
            "PE": "Peru",
            "VE": "Venezuela",
            "NZ": "New Zealand"
        }
        
        return country_names.get(country_code.upper(), country_code) 