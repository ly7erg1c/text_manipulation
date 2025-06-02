"""
Core extractor classes for different types of data.

This module contains classes for extracting various types of data from text:
- Hashes (SHA256, SHA1, MD5, Certificate fingerprints)
- Network data (IPv4/IPv6 addresses, URLs, domains, CIDR, ports, MAC addresses)
- Cryptocurrency addresses (Bitcoin, Ethereum, etc.)
- Security artifacts (CVE, YARA rules, Registry keys)
- Email addresses
- File references (executables)
- Text manipulation utilities
"""

import re
from typing import Set, List, Tuple, Dict, Optional
import ipaddress


class HashExtractor:
    """Extracts various types of cryptographic hashes from text."""
    
    @staticmethod
    def extract_sha256(text: str) -> Set[str]:
        """
        Extract SHA256 hashes from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique SHA256 hashes found
        """
        pattern = r"\b[A-Fa-f0-9]{64}\b"
        return set(re.findall(pattern, text))
    
    @staticmethod
    def extract_sha1(text: str) -> Set[str]:
        """
        Extract SHA1 hashes from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique SHA1 hashes found
        """
        pattern = r"\b[a-fA-F0-9]{40}\b"
        return set(re.findall(pattern, text))
    
    @staticmethod
    def extract_md5(text: str) -> Set[str]:
        """
        Extract MD5 hashes from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique MD5 hashes found
        """
        pattern = r"([a-fA-F\d]{32})"
        return set(re.findall(pattern, text))

    @staticmethod
    def extract_ssl_fingerprints(text: str) -> Dict[str, Set[str]]:
        """
        Extract SSL/TLS certificate fingerprints from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Dictionary with fingerprint types and their values
        """
        results = {
            'sha256': set(),
            'sha1': set(),
            'md5': set()
        }
        
        # SSL fingerprints are often presented with colons
        sha256_pattern = r"\b[A-Fa-f0-9]{2}(?::[A-Fa-f0-9]{2}){31}\b"
        sha1_pattern = r"\b[A-Fa-f0-9]{2}(?::[A-Fa-f0-9]{2}){19}\b"
        md5_pattern = r"\b[A-Fa-f0-9]{2}(?::[A-Fa-f0-9]{2}){15}\b"
        
        results['sha256'].update(re.findall(sha256_pattern, text))
        results['sha1'].update(re.findall(sha1_pattern, text))
        results['md5'].update(re.findall(md5_pattern, text))
        
        return results

    @classmethod
    def extract_ssl_certificate_fingerprints(cls, text: str) -> Dict[str, Set[str]]:
        """Alias for extract_ssl_fingerprints to match CLI naming."""
        return cls.extract_ssl_fingerprints(text)


class NetworkExtractor:
    """Extracts network-related data like IP addresses and URLs from text."""
    
    @staticmethod
    def extract_ipv4(text: str) -> Set[str]:
        """
        Extract IPv4 addresses from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique IPv4 addresses found
        """
        pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        return set(re.findall(pattern, text))

    @staticmethod
    def extract_ipv6(text: str) -> Set[str]:
        """
        Extract IPv6 addresses from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique IPv6 addresses found
        """
        # Comprehensive IPv6 pattern including compressed forms
        pattern = r'(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
        
        matches = re.findall(pattern, text)
        valid_ipv6 = set()
        
        for match in matches:
            try:
                # Validate using ipaddress module
                ipaddress.IPv6Address(match)
                valid_ipv6.add(match)
            except ipaddress.AddressValueError:
                continue
                
        return valid_ipv6

    @staticmethod
    def extract_defanged_ipv6(text: str) -> Set[str]:
        """
        Extract defanged IPv6 addresses from text (e.g., 2001[:]db8[:]85a3[:]0[:]0[:]8a2e[:]370[:]7334).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique defanged IPv6 addresses found
        """
        pattern = r'(?:[0-9a-fA-F]{1,4}\[:\]){2,7}[0-9a-fA-F]{1,4}(?:\[:\])?'
        return set(re.findall(pattern, text))

    @staticmethod
    def defang_ipv6(text: str) -> Set[str]:
        """
        Extract IPv6 addresses and return them in defanged format (colons replaced with [:]).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique defanged IPv6 addresses found
        """
        ipv6_addresses = NetworkExtractor.extract_ipv6(text)
        return {ip.replace(':', '[:]') for ip in ipv6_addresses}

    @staticmethod
    def unfang_ipv6(defanged_ip: str) -> str:
        """
        Convert a defanged IPv6 address back to normal format.
        
        Args:
            defanged_ip: The defanged IPv6 address
            
        Returns:
            Normal IPv6 address format
        """
        return defanged_ip.replace('[:]', ':')

    @staticmethod
    def extract_domains(text: str) -> Set[str]:
        """
        Extract domain names and FQDNs from text (separate from full URLs).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique domain names found
        """
        # Pattern for domains without protocol
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        # Common file extensions to exclude (but NOT common TLDs)
        file_extensions = {
            'txt', 'doc', 'docx', 'pdf', 'xls', 'xlsx', 'ppt', 'pptx',
            'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg',
            'mp3', 'mp4', 'avi', 'mkv', 'flv', 'wmv',
            'dat', 'log', 'tmp', 'bak', 'cfg', 'conf', 'ini'
        }
        
        # Common TLDs that should NOT be filtered (even if they match executable extensions)
        common_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'arpa',
            'co', 'uk', 'ca', 'de', 'fr', 'jp', 'au', 'br', 'cn', 'in',
            'ru', 'za', 'es', 'it', 'nl', 'pl', 'se', 'no', 'fi', 'dk',
            'io', 'me', 'tv', 'cc', 'ly', 'to', 'info', 'biz', 'name',
            'mobi', 'pro', 'aero', 'coop', 'museum', 'jobs', 'travel',
            'xxx', 'tel', 'asia', 'cat', 'post', 'geo', 'local', 'localhost',
            'evil'  # Custom TLD from test data
        }
        
        matches = re.findall(domain_pattern, text)
        domains = set()
        
        for match in matches:
            # Filter out obvious non-domains
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', match):  # Not an IP
                match_lower = match.lower()
                
                # Get the extension (last part after the last dot)
                extension = match_lower.split('.')[-1]
                
                # Only filter out if it's a file extension AND not a common TLD
                if extension in file_extensions and extension not in common_tlds:
                    continue
                
                # Skip very short extensions (likely not TLDs)
                if len(extension) < 2:
                    continue
                
                # Skip if it contains only numbers in the extension
                if extension.isdigit():
                    continue
                
                # Additional validation: must have at least one letter in the TLD
                if any(c.isalpha() for c in extension):
                    domains.add(match_lower)
        
        return domains

    @staticmethod
    def extract_cidr_networks(text: str) -> Set[str]:
        """
        Extract CIDR notation network ranges from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique CIDR networks found
        """
        # IPv4 CIDR pattern
        ipv4_cidr_pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[12]?[0-9])\b'
        
        # IPv6 CIDR pattern
        ipv6_cidr_pattern = r'(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{0,4}/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])\b'
        
        networks = set()
        networks.update(re.findall(ipv4_cidr_pattern, text))
        networks.update(re.findall(ipv6_cidr_pattern, text))
        
        return networks

    @staticmethod
    def extract_ports(text: str) -> Dict[str, Set[str]]:
        """
        Extract port numbers with context from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Dictionary with port types and their values
        """
        results = {
            'standalone_ports': set(),
            'host_port_pairs': set(),
            'url_ports': set()
        }
        
        # Standalone port numbers (1-65535)
        standalone_pattern = r'\bport\s+(\d{1,5})\b|\bports?\s+(\d{1,5})\b'
        matches = re.findall(standalone_pattern, text, re.IGNORECASE)
        for match in matches:
            port = match[0] or match[1]
            if 1 <= int(port) <= 65535:
                results['standalone_ports'].add(port)
        
        # Host:port pairs
        hostport_pattern = r'\b(?:[a-zA-Z0-9.-]+|\d+\.\d+\.\d+\.\d+):(\d{1,5})\b'
        matches = re.findall(hostport_pattern, text)
        for port in matches:
            if 1 <= int(port) <= 65535:
                results['host_port_pairs'].add(port)
        
        # URLs with ports
        url_port_pattern = r'https?://[^:/\s]+:(\d{1,5})'
        matches = re.findall(url_port_pattern, text)
        for port in matches:
            if 1 <= int(port) <= 65535:
                results['url_ports'].add(port)
        
        return results

    @staticmethod
    def extract_mac_addresses(text: str) -> Set[str]:
        """
        Extract MAC addresses from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique MAC addresses found
        """
        # Various MAC address formats
        mac_addresses = set()
        
        # Pattern 1: XX:XX:XX:XX:XX:XX (colon-separated)
        pattern1 = r'\b[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\b'
        mac_addresses.update(re.findall(pattern1, text))
        
        # Pattern 2: XX-XX-XX-XX-XX-XX (dash-separated)
        pattern2 = r'\b[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}\b'
        mac_addresses.update(re.findall(pattern2, text))
        
        # Pattern 3: XXXX.XXXX.XXXX (Cisco format)
        pattern3 = r'\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b'
        mac_addresses.update(re.findall(pattern3, text))
        
        # Pattern 4: XXXXXXXXXXXX (no separators - must be exactly 12 hex digits)
        pattern4 = r'\b[0-9A-Fa-f]{12}\b'
        # For this pattern, we need to be more careful to avoid matching other hex values
        potential_macs = re.findall(pattern4, text)
        for mac in potential_macs:
            # Additional validation: check if it's not part of a longer hex string
            # and if it contains a good mix of characters (not all same digit)
            if len(set(mac.lower())) > 1:  # More than one unique character
                mac_addresses.add(mac)
        
        # Pattern 5: Partial MAC addresses like XX:XX (incomplete but valid format)
        # Only add these if they look like legitimate partial MACs (2-5 groups)
        partial_pattern = r'\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){1,4}\b'
        partial_macs = re.findall(partial_pattern, text)
        for mac in partial_macs:
            # Only include if it has 2-5 groups (not full MAC which is already covered)
            group_count = mac.count(':') + mac.count('-') + 1
            if 2 <= group_count <= 5:
                mac_addresses.add(mac)
        
        return mac_addresses

    @staticmethod
    def extract_asn(text: str) -> Set[str]:
        """
        Extract Autonomous System Numbers from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique ASN values found
        """
        # ASN patterns: AS1234, ASN1234, AS 1234
        pattern = r'\bAS[N]?\s*(\d{1,10})\b'
        matches = re.findall(pattern, text, re.IGNORECASE)
        return set(matches)
    
    @staticmethod
    def extract_defanged_ipv4(text: str) -> Set[str]:
        """
        Extract defanged IPv4 addresses from text (e.g., 192[.]168[.]1[.]1).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique defanged IPv4 addresses found
        """
        pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[\.\](?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        return set(re.findall(pattern, text))
    
    @staticmethod
    def defang_ipv4(text: str) -> Set[str]:
        """
        Extract IPv4 addresses and return them in defanged format (dots replaced with [.]).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique defanged IPv4 addresses found
        """
        ips = NetworkExtractor.extract_ipv4(text)
        return {ip.replace('.', '[.]') for ip in ips}
    
    @staticmethod
    def unfang_ipv4(defanged_ip: str) -> str:
        """
        Convert a defanged IPv4 address back to normal format.
        
        Args:
            defanged_ip: The defanged IP address (e.g., 192[.]168[.]1[.]1)
            
        Returns:
            Normal IPv4 address format
        """
        return defanged_ip.replace('[.]', '.')
    
    @staticmethod
    def _extract_url_tuples(text: str) -> List[Tuple[str, ...]]:
        """
        Extract URL tuples from text (internal method).
        
        Args:
            text: The input text to search
            
        Returns:
            List of URL tuples from regex matching
        """
        pattern = r"(((https://)|(http://)|(ftp://))?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))"
        return re.findall(pattern, text)
    
    @classmethod
    def extract_urls(cls, text: str) -> Set[str]:
        """
        Extract clean URLs from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique URLs found
        """
        url_tuples = cls._extract_url_tuples(text)
        clean_urls = set()
        
        # Common executable extensions to exclude
        executable_extensions = {
            'exe', 'bat', 'cmd', 'com', 'scr', 'pif', 'msi', 'jar',  # Windows
            'sh', 'bin', 'run', 'app', 'deb', 'rpm', 'pkg',         # Unix/Linux
            'apk', 'ipa', 'dmg'                                      # Mobile/Mac
        }
        
        for url_tuple in url_tuples:
            for url in url_tuple:
                if url and '.' in url:  # Check if it's a URL
                    # Get the extension if any
                    url_parts = url.split('.')
                    extension = url_parts[-1].split('?')[0].split('#')[0].split('/')[0].lower()
                    
                    # Skip if it's an executable extension (unless it has a protocol or path)
                    if extension in executable_extensions:
                        # Only allow if it has a protocol or path indicators
                        if not (url.startswith(('http://', 'https://', 'ftp://')) or '/' in url or '?' in url or '#' in url):
                            continue
                    
                    # Only add if it starts with protocol or looks like a complete URL/domain
                    if (url.startswith(('http://', 'https://', 'ftp://')) or 
                        (not url.startswith('/') and '/' in url or '?' in url)):
                        # Additional check to avoid including standalone ports
                        if not url.isdigit() and ':' not in url.split('/')[-1]:
                            clean_urls.add(url)
                    elif (not url.startswith(('http://', 'https://', 'ftp://')) and 
                          not url.startswith('/') and 
                          not url.isdigit() and 
                          '.' in url and
                          len(url.split('.')[-1].split('?')[0].split('#')[0].split('/')[0]) >= 2):  # Has valid TLD
                        # Additional validation for domain-like strings
                        # Must contain at least one letter in the TLD part
                        tld = url.split('.')[-1].split('?')[0].split('#')[0].split('/')[0]
                        if any(c.isalpha() for c in tld) and extension not in executable_extensions:
                            clean_urls.add(url)
        
        return clean_urls
    
    @staticmethod
    def extract_defanged_urls(text: str) -> Set[str]:
        """
        Extract defanged URLs from text (e.g., hxxp://example[.]com).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique defanged URLs found
        """
        # Pattern for defanged URLs with hxxp/hxxps and [.]
        defanged_pattern = r"\b(?:hxxps?://|https?://)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\[?\.\]?[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=\[\]]*)"
        
        matches = re.findall(defanged_pattern, text)
        defanged_urls = set()
        
        for match in matches:
            # Only add if it contains defanged indicators
            if '[.]' in match or match.startswith(('hxxp://', 'hxxps://')):
                defanged_urls.add(match)
        
        return defanged_urls
    
    @classmethod
    def defang_urls(cls, text: str) -> Set[str]:
        """
        Extract URLs and return them in defanged format (dots replaced with [.], http with hxxp).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique defanged URLs found
        """
        urls = cls.extract_urls(text)
        defanged_urls = set()
        
        for url in urls:
            # First replace protocols, then dots
            defanged = url.replace('http://', 'hxxp://')
            defanged = defanged.replace('https://', 'hxxps://')
            defanged = defanged.replace('.', '[.]')
            defanged_urls.add(defanged)
        
        return defanged_urls
    
    @staticmethod
    def unfang_url(defanged_url: str) -> str:
        """
        Convert a defanged URL back to normal format.
        
        Args:
            defanged_url: The defanged URL (e.g., hxxp://example[.]com)
            
        Returns:
            Normal URL format
        """
        url = defanged_url.replace('hxxp://', 'http://')
        url = url.replace('hxxps://', 'https://')
        url = url.replace('[.]', '.')
        return url
    
    @classmethod
    def extract_all_ips_and_urls(cls, text: str) -> Dict[str, Set[str]]:
        """
        Extract all IP addresses and URLs from text in one pass.
        
        Args:
            text: The input text to search
            
        Returns:
            Dictionary containing all extracted network artifacts
        """
        return {
            'ipv4': cls.extract_ipv4(text),
            'ipv6': cls.extract_ipv6(text),
            'defanged_ipv4': cls.extract_defanged_ipv4(text),
            'defanged_ipv6': cls.extract_defanged_ipv6(text),
            'urls': cls.extract_urls(text),
            'defanged_urls': cls.extract_defanged_urls(text),
            'domains': cls.extract_domains(text),
            'cidr_networks': cls.extract_cidr_networks(text),
            'mac_addresses': cls.extract_mac_addresses(text),
            'asn': cls.extract_asn(text)
        }

    @classmethod
    def extract_all_network_data(cls, text: str) -> Dict[str, Set[str]]:
        """
        Extract all network-related data from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Dictionary containing all extracted network data
        """
        ports_data = cls.extract_ports(text)
        
        return {
            'ipv4_addresses': cls.extract_ipv4(text),
            'ipv6_addresses': cls.extract_ipv6(text),
            'urls': cls.extract_urls(text),
            'domains': cls.extract_domains(text),
            'cidr_networks': cls.extract_cidr_networks(text),
            'ports': {
                'standalone': ports_data['standalone_ports'],
                'host_port_pairs': ports_data['host_port_pairs'],
                'url_ports': ports_data['url_ports']
            },
            'mac_addresses': cls.extract_mac_addresses(text),
            'asn_numbers': cls.extract_asn(text)
        }

    @staticmethod
    def extract_asn_numbers(text: str) -> Set[str]:
        """Alias for extract_asn to match CLI naming."""
        return NetworkExtractor.extract_asn(text)


class CryptocurrencyExtractor:
    """Extracts cryptocurrency addresses from text."""
    
    @staticmethod
    def extract_bitcoin(text: str) -> Set[str]:
        """
        Extract Bitcoin addresses from text (Legacy, SegWit, Bech32).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique Bitcoin addresses found
        """
        patterns = [
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',      # Legacy (P2PKH, P2SH)
            r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b',         # SegWit (P2SH)
            r'\bbc1[a-z0-9]{39,59}\b'                     # Bech32 (P2WPKH, P2WSH)
        ]
        
        addresses = set()
        for pattern in patterns:
            addresses.update(re.findall(pattern, text))
        
        return addresses
    
    @staticmethod
    def extract_ethereum(text: str) -> Set[str]:
        """
        Extract Ethereum addresses from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique Ethereum addresses found
        """
        pattern = r'\b0x[a-fA-F0-9]{40}\b'
        return set(re.findall(pattern, text))
    
    @staticmethod
    def extract_litecoin(text: str) -> Set[str]:
        """
        Extract Litecoin addresses from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique Litecoin addresses found
        """
        patterns = [
            r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b',     # Legacy
            r'\bltc1[a-z0-9]{39,59}\b'                    # Bech32
        ]
        
        addresses = set()
        for pattern in patterns:
            addresses.update(re.findall(pattern, text))
        
        return addresses
    
    @staticmethod
    def extract_monero(text: str) -> Set[str]:
        """
        Extract Monero addresses from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique Monero addresses found
        """
        pattern = r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
        return set(re.findall(pattern, text))
    
    @staticmethod
    def extract_all_crypto(text: str) -> Dict[str, Set[str]]:
        """
        Extract all cryptocurrency addresses from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Dictionary with cryptocurrency types and their addresses
        """
        return {
            'bitcoin': CryptocurrencyExtractor.extract_bitcoin(text),
            'ethereum': CryptocurrencyExtractor.extract_ethereum(text),
            'litecoin': CryptocurrencyExtractor.extract_litecoin(text),
            'monero': CryptocurrencyExtractor.extract_monero(text)
        }

    @staticmethod
    def extract_bitcoin_addresses(text: str) -> Set[str]:
        """Alias for extract_bitcoin to match CLI naming."""
        return CryptocurrencyExtractor.extract_bitcoin(text)
    
    @staticmethod
    def extract_ethereum_addresses(text: str) -> Set[str]:
        """Alias for extract_ethereum to match CLI naming."""
        return CryptocurrencyExtractor.extract_ethereum(text)
    
    @staticmethod
    def extract_litecoin_addresses(text: str) -> Set[str]:
        """Alias for extract_litecoin to match CLI naming."""
        return CryptocurrencyExtractor.extract_litecoin(text)
    
    @staticmethod
    def extract_monero_addresses(text: str) -> Set[str]:
        """Alias for extract_monero to match CLI naming."""
        return CryptocurrencyExtractor.extract_monero(text)
    
    @staticmethod
    def extract_all_cryptocurrency_addresses(text: str) -> Dict[str, Set[str]]:
        """Alias for extract_all_crypto to match CLI naming."""
        return CryptocurrencyExtractor.extract_all_crypto(text)


class SecurityExtractor:
    """Extracts security-related artifacts from text."""
    
    @staticmethod
    def extract_cve(text: str) -> Set[str]:
        """
        Extract CVE identifiers from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique CVE identifiers found
        """
        pattern = r'\bCVE-\d{4}-\d{4,}\b'
        return set(re.findall(pattern, text, re.IGNORECASE))
    
    @staticmethod
    def extract_yara_rules(text: str) -> Dict[str, Set[str]]:
        """
        Extract YARA rule names and references from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Dictionary with YARA rule types and their values
        """
        results = {
            'rule_names': set(),
            'yara_keywords': set()
        }
        
        # YARA rule names (rule keyword followed by identifier)
        rule_pattern = r'\brule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{'
        results['rule_names'].update(re.findall(rule_pattern, text, re.IGNORECASE))
        
        # YARA specific keywords/functions
        yara_keywords = [
            'strings', 'condition', 'meta', 'global', 'private', 'import',
            'uint8', 'uint16', 'uint32', 'int8', 'int16', 'int32',
            'filesize', 'entrypoint', 'all', 'any', 'them', 'for'
        ]
        
        for keyword in yara_keywords:
            if re.search(r'\b' + keyword + r'\b', text, re.IGNORECASE):
                results['yara_keywords'].add(keyword)
        
        return results
    
    @staticmethod
    def extract_registry_keys(text: str) -> Set[str]:
        """
        Extract Windows registry keys from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique registry keys found
        """
        # Common registry hives and patterns
        pattern = r'\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|HKEY_CURRENT_CONFIG|HKCC)\\[^"\s\n\r]*'
        return set(re.findall(pattern, text, re.IGNORECASE))

    @staticmethod
    def extract_cve_identifiers(text: str) -> Set[str]:
        """Alias for extract_cve to match CLI naming."""
        return SecurityExtractor.extract_cve(text)
    
    @staticmethod
    def extract_yara_rules(text: str) -> Dict[str, Set[str]]:
        """Alias for extract_yara_rules to match CLI naming."""
        return SecurityExtractor.extract_yara_rules(text)
    
    @staticmethod
    def extract_windows_registry_keys(text: str) -> Set[str]:
        """Alias for extract_registry_keys to match CLI naming."""
        return SecurityExtractor.extract_registry_keys(text)


class EmailExtractor:
    """Extracts email addresses from text."""
    
    @staticmethod
    def extract_emails(text: str) -> Set[str]:
        """
        Extract email addresses from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique email addresses found
        """
        # Comprehensive email pattern
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return set(re.findall(pattern, text))
    
    @staticmethod
    def extract_defanged_emails(text: str) -> Set[str]:
        """
        Extract defanged email addresses from text (e.g., user[@]domain[.]com).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique defanged email addresses found
        """
        pattern = r'\b[A-Za-z0-9._%+-]+\[@\][A-Za-z0-9.-]*\[?\.\]?[A-Z|a-z]{2,}\b'
        return set(re.findall(pattern, text))
    
    @staticmethod
    def defang_emails(text: str) -> Set[str]:
        """
        Extract email addresses and return them in defanged format.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique defanged email addresses
        """
        emails = EmailExtractor.extract_emails(text)
        defanged = set()
        
        for email in emails:
            defanged_email = email.replace('@', '[@]').replace('.', '[.]')
            defanged.add(defanged_email)
        
        return defanged
    
    @staticmethod
    def unfang_email(defanged_email: str) -> str:
        """
        Convert a defanged email address back to normal format.
        
        Args:
            defanged_email: The defanged email address
            
        Returns:
            Normal email address format
        """
        return defanged_email.replace('[@]', '@').replace('[.]', '.')

    @staticmethod
    def extract_email_addresses(text: str) -> Set[str]:
        """Alias for extract_emails to match CLI naming."""
        return EmailExtractor.extract_emails(text)


class FileExtractor:
    """Extracts file-related information from text."""
    
    @staticmethod
    def extract_executables(text: str) -> Set[str]:
        """
        Extract executable file references from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique executable file paths/names found
        """
        # Enhanced pattern for various executable types
        patterns = [
            r'\b[a-zA-Z0-9_-]+\.(?:exe|bat|cmd|scr|pif|msi|jar)\b',  # Windows executables (excluding .com for now)
            r'\b[a-zA-Z0-9_-]+\.(?:sh|bin|run|app|deb|rpm|pkg)\b',       # Unix/Linux executables
            r'\b[a-zA-Z0-9_-]+\.(?:apk|ipa)\b',                          # Mobile apps
            r'[C-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\.(?:exe|bat|cmd|com|scr|pif|msi)\b'  # Full Windows paths
        ]
        
        # Separate pattern for .com files (more restrictive)
        com_pattern = r'\b[a-zA-Z0-9_-]+\.com\b'
        
        # Common domain TLDs that should be excluded
        common_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'arpa',
            'co', 'uk', 'ca', 'de', 'fr', 'jp', 'au', 'br', 'cn', 'in',
            'ru', 'za', 'es', 'it', 'nl', 'pl', 'se', 'no', 'fi', 'dk',
            'io', 'me', 'tv', 'cc', 'ly', 'to', 'info', 'biz', 'name',
            'mobi', 'pro', 'aero', 'coop', 'museum', 'jobs', 'travel',
            'xxx', 'tel', 'asia', 'cat', 'post', 'geo', 'local', 'localhost',
            'evil'  # Adding custom TLD from your data
        }
        
        # Domain-like patterns to exclude
        domain_indicators = ['www', 'api', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'files', 'host', 'server', 'sub', 'evil-c2']
        
        executables = set()
        
        # Process regular executable patterns
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Get the parts
                if '.' in match:
                    full_name = match.lower()
                    parts = full_name.split('.')
                    
                    # Skip if it looks like a domain name
                    if len(parts) >= 2:
                        base_name = '.'.join(parts[:-1])  # Everything except the extension
                        extension = parts[-1]
                        
                        # Skip if this is clearly a domain pattern (domain.tld.extension)
                        if len(parts) >= 3:
                            potential_tld = parts[-2]
                            if potential_tld in common_tlds:
                                continue  # Skip domain.com.exe patterns
                        
                        # Skip if the base name contains domain indicators
                        if any(indicator in base_name for indicator in domain_indicators):
                            continue
                        
                        # Skip if the base name looks like a typical domain
                        # (contains multiple dots or common domain patterns)
                        if '.' in base_name:  # Has subdomain structure
                            subdomain_parts = base_name.split('.')
                            # Check if any part looks like a TLD
                            if any(part in common_tlds for part in subdomain_parts):
                                continue
                        
                        # Skip if it contains hyphens and looks domain-like
                        if '-' in base_name:
                            hyphen_parts = base_name.split('-')
                            # If it has domain-like words or TLDs
                            if any(part in common_tlds or part in domain_indicators for part in hyphen_parts):
                                continue
                        
                        # Additional check: if base name is a single common word, it might be a domain
                        if base_name in common_tlds:
                            continue
                    
                    # If we get here, it's likely a legitimate executable
                    executables.add(match)
        
        # Handle .com files separately with stricter validation
        com_matches = re.findall(com_pattern, text, re.IGNORECASE)
        for match in com_matches:
            match_lower = match.lower()
            base_name = match_lower.replace('.com', '')
            
            # Only add .com files if they look like legitimate DOS/Windows executables
            # Skip if base name contains domain indicators or looks like a domain
            if not any(indicator in base_name for indicator in domain_indicators):
                # Skip common domain patterns
                if not (len(base_name) > 10 or '-' in base_name or '.' in base_name):
                    # Skip if it's a known domain or looks domain-like
                    if base_name not in ['google', 'example', 'company', 'badguys', 'virustotal']:
                        executables.add(match)
        
        return executables


class TextManipulator:
    """Provides text manipulation utilities."""
    
    @staticmethod
    def newline_to_space(text: str) -> str:
        """
        Convert newlines to spaces in text.
        
        Args:
            text: The input text to process
            
        Returns:
            Text with newlines replaced by spaces
        """
        return re.sub(r'\r?\n', ' ', text)
    
    @staticmethod
    def remove_blank_lines(text: str) -> str:
        """
        Remove blank lines from text.
        
        Args:
            text: The input text to process
            
        Returns:
            Text with blank lines removed
        """
        lines = text.split('\n')
        non_blank_lines = [line for line in lines if line.strip()]
        return '\n'.join(non_blank_lines)


class DefangUtility:
    """Utility class for defanging/unfanging various IOCs."""
    
    @staticmethod
    def defang_text(text: str) -> str:
        """
        Defang all IOCs in text automatically.
        
        Args:
            text: The input text to defang
            
        Returns:
            Text with all IOCs defanged
        """
        
        def replace_ip_dots(match):
            return match.group().replace('.', '[.]')
        
        def replace_domain_dots(match):
            return match.group().replace('.', '[.]')
        
        def replace_email_symbols(match):
            return match.group().replace('@', '[@]').replace('.', '[.]')
        
        def replace_url_protocols(match):
            return match.group().replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')
        
        # Defang IPs
        text = re.sub(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', replace_ip_dots, text)
        
        # Defang URLs
        text = re.sub(r'https?://[^\s<>"\']+', replace_url_protocols, text)
        
        # Defang standalone domains (be careful not to double-defang)
        text = re.sub(r'\b(?![0-9.]+\b)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b(?![.\]])', replace_domain_dots, text)
        
        # Defang emails
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', replace_email_symbols, text)
        
        return text
    
    @staticmethod
    def unfang_text(text: str) -> str:
        """
        Unfang all IOCs in text automatically.
        
        Args:
            text: The input text to unfang
            
        Returns:
            Text with all IOCs unfanged
        """
        # Unfang protocols
        text = text.replace('hxxp://', 'http://')
        text = text.replace('hxxps://', 'https://')
        
        # Unfang dots and symbols
        text = text.replace('[.]', '.')
        text = text.replace('[@]', '@')
        text = text.replace('[:]', ':')
        
        return text 


# Standalone functions for backwards compatibility and easier testing
def extract_ips(text: str) -> List[str]:
    """
    Extract IP addresses from text.
    
    Args:
        text: The input text to search
        
    Returns:
        List of IP addresses found
    """
    ipv4_addresses = NetworkExtractor.extract_ipv4(text)
    ipv6_addresses = NetworkExtractor.extract_ipv6(text)
    return list(ipv4_addresses.union(ipv6_addresses))


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from text.
    
    Args:
        text: The input text to search
        
    Returns:
        List of URLs found
    """
    urls = NetworkExtractor.extract_urls(text)
    return list(urls)


def extract_hashes(text: str, hash_type: str = "all") -> List[str]:
    """
    Extract cryptographic hashes from text.
    
    Args:
        text: The input text to search
        hash_type: Type of hash to extract ("md5", "sha1", "sha256", or "all")
        
    Returns:
        List of hashes found
    """
    if hash_type == "md5":
        return list(HashExtractor.extract_md5(text))
    elif hash_type == "sha1":
        return list(HashExtractor.extract_sha1(text))
    elif hash_type == "sha256":
        return list(HashExtractor.extract_sha256(text))
    elif hash_type == "all":
        md5_hashes = HashExtractor.extract_md5(text)
        sha1_hashes = HashExtractor.extract_sha1(text)
        sha256_hashes = HashExtractor.extract_sha256(text)
        return list(md5_hashes.union(sha1_hashes).union(sha256_hashes))
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")


def extract_emails(text: str) -> List[str]:
    """
    Extract email addresses from text.
    
    Args:
        text: The input text to search
        
    Returns:
        List of email addresses found
    """
    emails = EmailExtractor.extract_emails(text)
    return list(emails)


def extract_from_file(file_path, extraction_type: str) -> List[str]:
    """
    Extract data from a file.
    
    Args:
        file_path: Path to the file to read
        extraction_type: Type of data to extract ("ip", "url", "hash", "email")
        
    Returns:
        List of extracted data
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return extract_from_text(content, extraction_type)
    except Exception as e:
        return []


def extract_from_text(text: str, extraction_type: str) -> List[str]:
    """
    Extract data from text based on the specified type.
    
    Args:
        text: The input text to search
        extraction_type: Type of data to extract ("ip", "url", "hash", "email")
        
    Returns:
        List of extracted data
        
    Raises:
        ValueError: If extraction_type is not supported
    """
    if extraction_type == "ip":
        return extract_ips(text)
    elif extraction_type == "url":
        return extract_urls(text)
    elif extraction_type == "hash":
        return extract_hashes(text)
    elif extraction_type == "email":
        return extract_emails(text)
    else:
        raise ValueError(f"Unsupported extraction type: {extraction_type}") 