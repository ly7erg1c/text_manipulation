"""
Shodan API Client

Provides device and service information from Shodan's internet-wide scanning data.
"""

import asyncio
import aiohttp
from typing import Dict, Any, Optional, List
import logging
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class ShodanClient:
    """Client for querying Shodan API."""
    
    def __init__(self, api_key: str):
        """
        Initialize Shodan client.
        
        Args:
            api_key: Shodan API key
        """
        self.api_key = api_key
        self.base_url = 'https://api.shodan.io'
        self.headers = {}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def query_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Query Shodan for information about an IP address.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary containing Shodan results
        """
        try:
            url = f"{self.base_url}/shodan/host/{ip_address}"
            params = {'key': self.api_key}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._format_ip_response(data, ip_address)
                    elif response.status == 404:
                        return {
                            'ip': ip_address,
                            'error': 'No information available',
                            'ports': [],
                            'vulnerabilities': [],
                            'tags': []
                        }
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        except Exception as e:
            logger.error(f"Error querying Shodan for IP {ip_address}: {e}")
            return {'error': str(e)}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def search(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """
        Search Shodan for devices/services.
        
        Args:
            query: Search query
            limit: Maximum number of results to return
            
        Returns:
            Dictionary containing search results
        """
        try:
            url = f"{self.base_url}/shodan/host/search"
            params = {
                'key': self.api_key,
                'query': query,
                'limit': limit
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._format_search_response(data, query)
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        except Exception as e:
            logger.error(f"Error searching Shodan with query '{query}': {e}")
            return {'error': str(e)}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def get_ports(self, ip_address: str) -> Dict[str, Any]:
        """
        Get open ports for an IP address.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary containing port information
        """
        try:
            url = f"{self.base_url}/shodan/host/{ip_address}"
            params = {'key': self.api_key, 'minify': 'true'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._format_ports_response(data, ip_address)
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        except Exception as e:
            logger.error(f"Error getting ports for IP {ip_address}: {e}")
            return {'error': str(e)}
    
    async def get_vulnerabilities(self, ip_address: str) -> Dict[str, Any]:
        """
        Get known vulnerabilities for an IP address.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary containing vulnerability information
        """
        try:
            # Get full host information first
            host_info = await self.query_ip(ip_address)
            
            if 'error' in host_info:
                return host_info
            
            return {
                'ip': ip_address,
                'vulnerabilities': host_info.get('vulnerabilities', []),
                'cves': host_info.get('cves', []),
                'risk_score': self._calculate_risk_score(host_info)
            }
        except Exception as e:
            logger.error(f"Error getting vulnerabilities for IP {ip_address}: {e}")
            return {'error': str(e)}
    
    def _format_ip_response(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Format Shodan IP response."""
        result = {
            'ip': ip_address,
            'hostnames': data.get('hostnames', []),
            'domains': data.get('domains', []),
            'country_code': data.get('country_code', ''),
            'country_name': data.get('country_name', ''),
            'city': data.get('city', ''),
            'region_code': data.get('region_code', ''),
            'postal_code': data.get('postal_code', ''),
            'latitude': data.get('latitude', 0),
            'longitude': data.get('longitude', 0),
            'isp': data.get('isp', ''),
            'org': data.get('org', ''),
            'asn': data.get('asn', ''),
            'last_update': data.get('last_update', ''),
            'ports': [],
            'services': [],
            'vulnerabilities': data.get('vulns', []),
            'cves': [],
            'tags': data.get('tags', []),
            'os': data.get('os', '')
        }
        
        # Extract port and service information
        for service_data in data.get('data', []):
            port = service_data.get('port', 0)
            if port:
                result['ports'].append(port)
            
            service_info = {
                'port': port,
                'protocol': service_data.get('transport', ''),
                'service': service_data.get('product', ''),
                'version': service_data.get('version', ''),
                'banner': service_data.get('data', ''),
                'timestamp': service_data.get('timestamp', ''),
                'ssl': service_data.get('ssl', {}),
                'http': service_data.get('http', {}),
                'location': {
                    'country_code': service_data.get('location', {}).get('country_code', ''),
                    'city': service_data.get('location', {}).get('city', '')
                }
            }
            
            # Extract CVEs from service data
            if 'vulns' in service_data:
                result['cves'].extend(service_data['vulns'])
            
            result['services'].append(service_info)
        
        # Remove duplicate ports and CVEs
        result['ports'] = list(set(result['ports']))
        result['cves'] = list(set(result['cves']))
        
        return result
    
    def _format_search_response(self, data: Dict[str, Any], query: str) -> Dict[str, Any]:
        """Format Shodan search response."""
        result = {
            'query': query,
            'total': data.get('total', 0),
            'matches': []
        }
        
        for match in data.get('matches', []):
            match_info = {
                'ip': match.get('ip_str', ''),
                'port': match.get('port', 0),
                'protocol': match.get('transport', ''),
                'service': match.get('product', ''),
                'version': match.get('version', ''),
                'banner': match.get('data', ''),
                'timestamp': match.get('timestamp', ''),
                'country': match.get('location', {}).get('country_name', ''),
                'city': match.get('location', {}).get('city', ''),
                'isp': match.get('isp', ''),
                'org': match.get('org', ''),
                'hostnames': match.get('hostnames', []),
                'domains': match.get('domains', [])
            }
            result['matches'].append(match_info)
        
        return result
    
    def _format_ports_response(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Format Shodan ports response."""
        result = {
            'ip': ip_address,
            'ports': []
        }
        
        for service_data in data.get('data', []):
            port_info = {
                'port': service_data.get('port', 0),
                'protocol': service_data.get('transport', ''),
                'service': service_data.get('product', ''),
                'state': 'open',  # Shodan only shows open ports
                'banner': service_data.get('data', '')[:200]  # Truncate banner
            }
            result['ports'].append(port_info)
        
        return result
    
    def _calculate_risk_score(self, host_info: Dict[str, Any]) -> int:
        """Calculate a basic risk score based on available information."""
        score = 0
        
        # Vulnerabilities add to risk
        vulns = len(host_info.get('vulnerabilities', []))
        cves = len(host_info.get('cves', []))
        score += vulns * 10 + cves * 5
        
        # Open ports add minor risk
        ports = len(host_info.get('ports', []))
        score += min(ports, 10)  # Cap port contribution
        
        # Common risky services
        risky_services = ['ftp', 'telnet', 'smtp', 'dns', 'http', 'pop3', 
                         'netbios', 'imap', 'snmp', 'rdp', 'ssh']
        
        for service in host_info.get('services', []):
            service_name = service.get('service', '').lower()
            if any(risky in service_name for risky in risky_services):
                score += 2
        
        # Normalize to 0-100 scale
        return min(score, 100) 