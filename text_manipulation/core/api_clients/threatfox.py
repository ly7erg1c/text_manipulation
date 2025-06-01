"""
ThreatFox API Client

Provides IOC (Indicators of Compromise) data from ThreatFox database.
"""

import asyncio
import aiohttp
from typing import Dict, Any, Optional, List
import logging
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class ThreatFoxClient:
    """Client for querying ThreatFox IOC database."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize ThreatFox client.
        
        Args:
            api_key: Optional API key (ThreatFox is free but rate limited)
        """
        self.api_key = api_key
        self.base_url = 'https://threatfox-api.abuse.ch/api/v1/'
        self.headers = {
            'Content-Type': 'application/json'
        }
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def query_ioc(self, ioc: str) -> Dict[str, Any]:
        """
        Query ThreatFox for information about an IOC.
        
        Args:
            ioc: IOC to query (hash, IP, domain, URL)
            
        Returns:
            Dictionary containing ThreatFox results
        """
        try:
            payload = {
                'query': 'search_ioc',
                'search_term': ioc
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.base_url,
                    json=payload,
                    headers=self.headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._format_ioc_response(data, ioc)
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        except Exception as e:
            logger.error(f"Error querying ThreatFox for IOC {ioc}: {e}")
            return {'error': str(e)}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def query_hash(self, hash_value: str) -> Dict[str, Any]:
        """
        Query ThreatFox for hash information.
        
        Args:
            hash_value: Hash to query (MD5, SHA1, SHA256)
            
        Returns:
            Dictionary containing hash information
        """
        try:
            payload = {
                'query': 'search_hash',
                'hash': hash_value
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.base_url,
                    json=payload,
                    headers=self.headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._format_hash_response(data, hash_value)
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        except Exception as e:
            logger.error(f"Error querying ThreatFox for hash {hash_value}: {e}")
            return {'error': str(e)}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def get_recent_iocs(self, days: int = 1) -> Dict[str, Any]:
        """
        Get recent IOCs from ThreatFox.
        
        Args:
            days: Number of days to look back (max 7)
            
        Returns:
            Dictionary containing recent IOCs
        """
        try:
            payload = {
                'query': 'get_iocs',
                'days': min(days, 7)  # API limit
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.base_url,
                    json=payload,
                    headers=self.headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._format_recent_iocs_response(data, days)
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        except Exception as e:
            logger.error(f"Error getting recent IOCs from ThreatFox: {e}")
            return {'error': str(e)}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def search_malware(self, malware_family: str) -> Dict[str, Any]:
        """
        Search for IOCs by malware family.
        
        Args:
            malware_family: Name of malware family
            
        Returns:
            Dictionary containing malware-related IOCs
        """
        try:
            payload = {
                'query': 'search_tag',
                'tag': malware_family,
                'limit': 50
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.base_url,
                    json=payload,
                    headers=self.headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._format_malware_response(data, malware_family)
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        except Exception as e:
            logger.error(f"Error searching ThreatFox for malware {malware_family}: {e}")
            return {'error': str(e)}
    
    async def get_tags(self) -> Dict[str, Any]:
        """
        Get available tags/malware families from ThreatFox.
        
        Returns:
            Dictionary containing available tags
        """
        try:
            payload = {
                'query': 'get_taginfo'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.base_url,
                    json=payload,
                    headers=self.headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._format_tags_response(data)
                    else:
                        return {'error': f'HTTP {response.status}: {await response.text()}'}
        except Exception as e:
            logger.error(f"Error getting tags from ThreatFox: {e}")
            return {'error': str(e)}
    
    def _format_ioc_response(self, data: Dict[str, Any], ioc: str) -> Dict[str, Any]:
        """Format ThreatFox IOC response."""
        result = {
            'provider': 'ThreatFox',
            'query': ioc,
            'query_status': data.get('query_status', ''),
            'iocs': []
        }
        
        if data.get('query_status') == 'ok' and 'data' in data:
            for item in data['data']:
                ioc_info = {
                    'id': item.get('id', ''),
                    'ioc': item.get('ioc', ''),
                    'ioc_type': item.get('ioc_type', ''),
                    'threat_type': item.get('threat_type', ''),
                    'malware': item.get('malware', ''),
                    'malware_printable': item.get('malware_printable', ''),
                    'malware_alias': item.get('malware_alias', ''),
                    'confidence_level': item.get('confidence_level', 0),
                    'first_seen': item.get('first_seen', ''),
                    'last_seen': item.get('last_seen', ''),
                    'reference': item.get('reference', ''),
                    'reporter': item.get('reporter', ''),
                    'tags': item.get('tags', [])
                }
                result['iocs'].append(ioc_info)
        
        result['total_results'] = len(result['iocs'])
        return result
    
    def _format_hash_response(self, data: Dict[str, Any], hash_value: str) -> Dict[str, Any]:
        """Format ThreatFox hash response."""
        result = {
            'provider': 'ThreatFox',
            'hash': hash_value,
            'query_status': data.get('query_status', ''),
            'malware_info': []
        }
        
        if data.get('query_status') == 'ok' and 'data' in data:
            for item in data['data']:
                malware_info = {
                    'id': item.get('id', ''),
                    'malware': item.get('malware', ''),
                    'malware_printable': item.get('malware_printable', ''),
                    'malware_alias': item.get('malware_alias', ''),
                    'signature': item.get('signature', ''),
                    'first_seen': item.get('first_seen', ''),
                    'last_seen': item.get('last_seen', ''),
                    'confidence_level': item.get('confidence_level', 0),
                    'reporter': item.get('reporter', ''),
                    'intelligence': {
                        'downloads': item.get('intelligence', {}).get('downloads', []),
                        'uploads': item.get('intelligence', {}).get('uploads', []),
                        'mail': item.get('intelligence', {}).get('mail', [])
                    }
                }
                result['malware_info'].append(malware_info)
        
        return result
    
    def _format_recent_iocs_response(self, data: Dict[str, Any], days: int) -> Dict[str, Any]:
        """Format ThreatFox recent IOCs response."""
        result = {
            'provider': 'ThreatFox',
            'query_type': 'recent_iocs',
            'days': days,
            'query_status': data.get('query_status', ''),
            'iocs_by_type': {
                'ip:port': [],
                'domain': [],
                'url': [],
                'payload': []
            },
            'total_count': 0
        }
        
        if data.get('query_status') == 'ok' and 'data' in data:
            for item in data['data']:
                ioc_type = item.get('ioc_type', '')
                ioc_info = {
                    'ioc': item.get('ioc', ''),
                    'malware': item.get('malware_printable', ''),
                    'threat_type': item.get('threat_type', ''),
                    'confidence': item.get('confidence_level', 0),
                    'first_seen': item.get('first_seen', ''),
                    'tags': item.get('tags', [])
                }
                
                if ioc_type in result['iocs_by_type']:
                    result['iocs_by_type'][ioc_type].append(ioc_info)
                else:
                    # Default category for unknown types
                    if 'other' not in result['iocs_by_type']:
                        result['iocs_by_type']['other'] = []
                    result['iocs_by_type']['other'].append(ioc_info)
                
                result['total_count'] += 1
        
        return result
    
    def _format_malware_response(self, data: Dict[str, Any], malware_family: str) -> Dict[str, Any]:
        """Format ThreatFox malware search response."""
        result = {
            'provider': 'ThreatFox',
            'malware_family': malware_family,
            'query_status': data.get('query_status', ''),
            'iocs': [],
            'statistics': {
                'ip_port': 0,
                'domain': 0,
                'url': 0,
                'payload': 0
            }
        }
        
        if data.get('query_status') == 'ok' and 'data' in data:
            for item in data['data']:
                ioc_info = {
                    'id': item.get('id', ''),
                    'ioc': item.get('ioc', ''),
                    'ioc_type': item.get('ioc_type', ''),
                    'threat_type': item.get('threat_type', ''),
                    'confidence_level': item.get('confidence_level', 0),
                    'first_seen': item.get('first_seen', ''),
                    'last_seen': item.get('last_seen', ''),
                    'reference': item.get('reference', ''),
                    'tags': item.get('tags', [])
                }
                result['iocs'].append(ioc_info)
                
                # Update statistics
                ioc_type = item.get('ioc_type', '')
                if ioc_type.replace(':', '_') in result['statistics']:
                    result['statistics'][ioc_type.replace(':', '_')] += 1
        
        result['total_results'] = len(result['iocs'])
        return result
    
    def _format_tags_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format ThreatFox tags response."""
        result = {
            'provider': 'ThreatFox',
            'query_status': data.get('query_status', ''),
            'tags': []
        }
        
        if data.get('query_status') == 'ok' and 'data' in data:
            for tag, count in data['data'].items():
                result['tags'].append({
                    'name': tag,
                    'count': count
                })
            
            # Sort by count descending
            result['tags'].sort(key=lambda x: x['count'], reverse=True)
        
        return result 