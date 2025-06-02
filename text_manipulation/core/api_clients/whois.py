"""
WHOIS API Client

Provides WHOIS registration data for domains and IP addresses.
"""

import asyncio
import aiohttp
import socket
from typing import Dict, Any, Optional
import logging
from tenacity import retry, stop_after_attempt, wait_exponential
import re

logger = logging.getLogger(__name__)


class WhoisClient:
    """Client for querying WHOIS data."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize WHOIS client.
        
        Args:
            api_key: Optional API key for enhanced services
        """
        self.api_key = api_key
        self.whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'biz': 'whois.neulevel.biz',
            'name': 'whois.nic.name',
            'mobi': 'whois.dotmobiregistry.net',
            'travel': 'whois.nic.travel',
            'pro': 'whois.registrypro.pro',
            'aero': 'whois.information.aero',
            'asia': 'whois.nic.asia',
            'cat': 'whois.cat',
            'coop': 'whois.nic.coop',
            'edu': 'whois.educause.edu',
            'gov': 'whois.nic.gov',
            'int': 'whois.iana.org',
            'jobs': 'whois.nic.jobs',
            'mil': 'whois.nic.mil',
            'museum': 'whois.museum',
            'tel': 'whois.nic.tel',
            'xxx': 'whois.nic.xxx'
        }
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def query_domain(self, domain: str) -> Dict[str, Any]:
        """
        Query WHOIS data for a domain.
        
        Args:
            domain: Domain name to query
            
        Returns:
            Dictionary containing WHOIS results
        """
        try:
            if self.api_key:
                return await self._query_whois_api(domain, 'domain')
            else:
                return await self._query_whois_raw(domain)
        except Exception as e:
            logger.error(f"Error querying WHOIS for domain {domain}: {e}")
            return {'error': str(e)}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def query_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Query WHOIS data for an IP address.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary containing WHOIS results
        """
        try:
            if self.api_key:
                return await self._query_whois_api(ip_address, 'ip')
            else:
                return await self._query_ip_whois_raw(ip_address)
        except Exception as e:
            logger.error(f"Error querying WHOIS for IP {ip_address}: {e}")
            return {'error': str(e)}
    
    async def _query_whois_api(self, query: str, query_type: str) -> Dict[str, Any]:
        """Query WHOIS using API service (placeholder for various APIs)."""
        # This is a placeholder for API-based WHOIS services
        # You can integrate with services like WhoisXML API, IPWhois API, etc.
        url = f"https://api.whoisxmlapi.com/v1"
        headers = {'Authorization': f'Bearer {self.api_key}'}
        
        params = {
            'domainName' if query_type == 'domain' else 'ipAddress': query,
            'outputFormat': 'JSON'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._format_api_response(data, query_type)
                else:
                    return {'error': f'HTTP {response.status}: {await response.text()}'}
    
    async def _query_whois_raw(self, domain: str) -> Dict[str, Any]:
        """Query WHOIS using raw socket connection."""
        try:
            # Get TLD
            tld = domain.split('.')[-1].lower()
            whois_server = self.whois_servers.get(tld, 'whois.iana.org')
            
            # Connect to WHOIS server
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(whois_server, 43),
                timeout=10
            )
            
            # Send query
            query = f"{domain}\r\n"
            writer.write(query.encode())
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(-1), timeout=30)
            writer.close()
            await writer.wait_closed()
            
            whois_data = response.decode('utf-8', errors='ignore')
            return self._parse_whois_data(whois_data, domain, 'domain')
            
        except Exception as e:
            return {'error': f'Raw WHOIS query failed: {str(e)}'}
    
    async def _query_ip_whois_raw(self, ip_address: str) -> Dict[str, Any]:
        """Query IP WHOIS using raw socket connection."""
        try:
            # Use ARIN WHOIS server for IP queries
            whois_server = 'whois.arin.net'
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(whois_server, 43),
                timeout=10
            )
            
            # Send query
            query = f"{ip_address}\r\n"
            writer.write(query.encode())
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(-1), timeout=30)
            writer.close()
            await writer.wait_closed()
            
            whois_data = response.decode('utf-8', errors='ignore')
            return self._parse_whois_data(whois_data, ip_address, 'ip')
            
        except Exception as e:
            return {'error': f'Raw IP WHOIS query failed: {str(e)}'}
    
    def _parse_whois_data(self, whois_text: str, query: str, query_type: str) -> Dict[str, Any]:
        """Parse raw WHOIS text data."""
        result = {
            'query': query,
            'query_type': query_type,
            'raw_data': whois_text,
            'parsed_data': {}
        }
        
        if query_type == 'domain':
            result['parsed_data'] = self._parse_domain_whois(whois_text)
        else:
            result['parsed_data'] = self._parse_ip_whois(whois_text)
        
        return result
    
    def _parse_domain_whois(self, whois_text: str) -> Dict[str, Any]:
        """Parse domain WHOIS data."""
        parsed = {}
        
        # Common WHOIS fields
        patterns = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)|Created:\s*(.+)',
            'expiration_date': r'Expiration Date:\s*(.+)|Expires:\s*(.+)',
            'updated_date': r'Updated Date:\s*(.+)|Modified:\s*(.+)',
            'status': r'Status:\s*(.+)',
            'name_servers': r'Name Server:\s*(.+)',
            'registrant_name': r'Registrant Name:\s*(.+)',
            'registrant_org': r'Registrant Organization:\s*(.+)',
            'registrant_email': r'Registrant Email:\s*(.+)',
            'admin_name': r'Admin Name:\s*(.+)',
            'admin_email': r'Admin Email:\s*(.+)',
            'tech_name': r'Tech Name:\s*(.+)',
            'tech_email': r'Tech Email:\s*(.+)'
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
            if match:
                value = match.group(1) or match.group(2) if len(match.groups()) > 1 else match.group(1)
                if value:
                    parsed[field] = value.strip()
        
        # Extract name servers as list
        ns_matches = re.findall(r'Name Server:\s*(.+)', whois_text, re.IGNORECASE)
        if ns_matches:
            parsed['name_servers'] = [ns.strip() for ns in ns_matches]
        
        return parsed
    
    def _parse_ip_whois(self, whois_text: str) -> Dict[str, Any]:
        """Parse IP WHOIS data."""
        parsed = {}
        
        patterns = {
            'net_range': r'NetRange:\s*(.+)',
            'cidr': r'CIDR:\s*(.+)',
            'net_name': r'NetName:\s*(.+)',
            'net_handle': r'NetHandle:\s*(.+)',
            'parent': r'Parent:\s*(.+)',
            'net_type': r'NetType:\s*(.+)',
            'origin_as': r'OriginAS:\s*(.+)',
            'organization': r'Organization:\s*(.+)|OrgName:\s*(.+)',
            'org_id': r'OrgId:\s*(.+)',
            'country': r'Country:\s*(.+)',
            'state_prov': r'StateProv:\s*(.+)',
            'city': r'City:\s*(.+)',
            'postal_code': r'PostalCode:\s*(.+)',
            'reg_date': r'RegDate:\s*(.+)',
            'updated': r'Updated:\s*(.+)',
            'abuse_handle': r'OrgAbuseHandle:\s*(.+)',
            'abuse_name': r'OrgAbuseName:\s*(.+)',
            'abuse_email': r'OrgAbuseEmail:\s*(.+)',
            'tech_handle': r'OrgTechHandle:\s*(.+)',
            'tech_name': r'OrgTechName:\s*(.+)',
            'tech_email': r'OrgTechEmail:\s*(.+)'
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
            if match:
                value = match.group(1) or match.group(2) if len(match.groups()) > 1 else match.group(1)
                if value:
                    parsed[field] = value.strip()
        
        return parsed
    
    def _format_api_response(self, data: Dict[str, Any], query_type: str) -> Dict[str, Any]:
        """Format API response data."""
        result = {
            'provider': 'API Service',
            'query_type': query_type,
            'data': data
        }
        
        # This would be customized based on the specific API being used
        # For now, just pass through the data
        return result 