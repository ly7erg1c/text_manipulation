"""
Passive DNS API Client

Provides passive DNS resolution data for domains and IP addresses
from various passive DNS providers.
"""

import asyncio
import aiohttp
from typing import Dict, Any, Optional, List
import logging
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class PassiveDNSClient:
    """Client for querying passive DNS data from multiple providers."""
    
    def __init__(self, api_key: Optional[str] = None, provider: str = "virustotal"):
        """
        Initialize Passive DNS client.
        
        Args:
            api_key: API key for the chosen provider
            provider: DNS provider to use (virustotal, circl, etc.)
        """
        self.api_key = api_key
        self.provider = provider.lower()
        self.base_urls = {
            'virustotal': 'https://www.virustotal.com/vtapi/v2',
            'circl': 'https://www.circl.lu/pdns/query',
            'farsight': 'https://api.dnsdb.info'
        }
        
        self.headers = {}
        if self.api_key:
            if self.provider == 'virustotal':
                self.headers = {'apikey': self.api_key}
            elif self.provider == 'farsight':
                self.headers = {'X-API-Key': self.api_key}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def query_domain(self, domain: str) -> Dict[str, Any]:
        """
        Query passive DNS data for a domain.
        
        Args:
            domain: Domain name to query
            
        Returns:
            Dictionary containing passive DNS results
        """
        try:
            if self.provider == 'virustotal':
                return await self._query_virustotal_domain(domain)
            elif self.provider == 'circl':
                return await self._query_circl_domain(domain)
            else:
                return {'error': f'Unsupported provider: {self.provider}'}
        except Exception as e:
            logger.error(f"Error querying passive DNS for domain {domain}: {e}")
            return {'error': str(e)}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def query_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Query passive DNS data for an IP address.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary containing passive DNS results
        """
        try:
            if self.provider == 'virustotal':
                return await self._query_virustotal_ip(ip_address)
            elif self.provider == 'circl':
                return await self._query_circl_ip(ip_address)
            else:
                return {'error': f'Unsupported provider: {self.provider}'}
        except Exception as e:
            logger.error(f"Error querying passive DNS for IP {ip_address}: {e}")
            return {'error': str(e)}
    
    async def _query_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Query VirusTotal passive DNS for domain."""
        if not self.api_key:
            return {'error': 'API key required for VirusTotal'}
        
        url = f"{self.base_urls['virustotal']}/domain/report"
        params = {'domain': domain, 'apikey': self.api_key}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._format_virustotal_domain_response(data)
                else:
                    return {'error': f'HTTP {response.status}: {await response.text()}'}
    
    async def _query_virustotal_ip(self, ip_address: str) -> Dict[str, Any]:
        """Query VirusTotal passive DNS for IP address."""
        if not self.api_key:
            return {'error': 'API key required for VirusTotal'}
        
        url = f"{self.base_urls['virustotal']}/ip-address/report"
        params = {'ip': ip_address, 'apikey': self.api_key}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._format_virustotal_ip_response(data)
                else:
                    return {'error': f'HTTP {response.status}: {await response.text()}'}
    
    async def _query_circl_domain(self, domain: str) -> Dict[str, Any]:
        """Query CIRCL passive DNS for domain."""
        url = f"{self.base_urls['circl']}/{domain}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    text_data = await response.text()
                    return self._format_circl_response(text_data, 'domain')
                else:
                    return {'error': f'HTTP {response.status}: {await response.text()}'}
    
    async def _query_circl_ip(self, ip_address: str) -> Dict[str, Any]:
        """Query CIRCL passive DNS for IP address."""
        url = f"{self.base_urls['circl']}/{ip_address}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    text_data = await response.text()
                    return self._format_circl_response(text_data, 'ip')
                else:
                    return {'error': f'HTTP {response.status}: {await response.text()}'}
    
    def _format_virustotal_domain_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format VirusTotal domain response."""
        result = {
            'provider': 'VirusTotal',
            'query_type': 'domain',
            'response_code': data.get('response_code', 0),
            'detected_urls': [],
            'resolutions': [],
            'subdomains': []
        }
        
        if 'detected_urls' in data:
            result['detected_urls'] = [
                {
                    'url': item['url'],
                    'positives': item['positives'],
                    'total': item['total'],
                    'scan_date': item['scan_date']
                }
                for item in data['detected_urls'][:10]  # Limit to 10
            ]
        
        if 'resolutions' in data:
            result['resolutions'] = [
                {
                    'ip_address': item['ip_address'],
                    'last_resolved': item['last_resolved']
                }
                for item in data['resolutions'][:20]  # Limit to 20
            ]
        
        if 'subdomains' in data:
            result['subdomains'] = data['subdomains'][:20]  # Limit to 20
        
        return result
    
    def _format_virustotal_ip_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format VirusTotal IP response."""
        result = {
            'provider': 'VirusTotal',
            'query_type': 'ip',
            'response_code': data.get('response_code', 0),
            'detected_urls': [],
            'resolutions': []
        }
        
        if 'detected_urls' in data:
            result['detected_urls'] = [
                {
                    'url': item['url'],
                    'positives': item['positives'],
                    'total': item['total'],
                    'scan_date': item['scan_date']
                }
                for item in data['detected_urls'][:10]  # Limit to 10
            ]
        
        if 'resolutions' in data:
            result['resolutions'] = [
                {
                    'hostname': item['hostname'],
                    'last_resolved': item['last_resolved']
                }
                for item in data['resolutions'][:20]  # Limit to 20
            ]
        
        return result
    
    def _format_circl_response(self, text_data: str, query_type: str) -> Dict[str, Any]:
        """Format CIRCL passive DNS response."""
        result = {
            'provider': 'CIRCL',
            'query_type': query_type,
            'records': []
        }
        
        lines = text_data.strip().split('\n')
        for line in lines:
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 3:
                    record = {
                        'timestamp': parts[0] if len(parts) > 0 else '',
                        'rrname': parts[1] if len(parts) > 1 else '',
                        'rrtype': parts[2] if len(parts) > 2 else '',
                        'rdata': parts[3] if len(parts) > 3 else ''
                    }
                    result['records'].append(record)
        
        return result 