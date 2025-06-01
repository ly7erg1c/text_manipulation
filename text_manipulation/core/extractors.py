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
        
        matches = re.findall(domain_pattern, text)
        domains = set()
        
        for match in matches:
            # Filter out obvious non-domains
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', match):  # Not an IP
                domains.add(match.lower())
        
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
        patterns = [
            r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',  # XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
            r'\b([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b',      # XXXX.XXXX.XXXX
            r'\b[0-9A-Fa-f]{12}\b'                            # XXXXXXXXXXXX
        ]
        
        mac_addresses = set()
        for pattern in patterns:
            matches = re.findall(pattern, text)
            if isinstance(matches[0], tuple) if matches else False:
                # For patterns with groups, reconstruct the full match
                for match in matches:
                    if len(match) == 2:  # Colon/dash separated
                        mac_addresses.add(''.join(match))
            else:
                mac_addresses.update(matches)
        
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
        pattern = r"(((https://)|(http://))?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))"
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
        
        for url_tuple in url_tuples:
            for url in url_tuple:
                if url and '.' in url:  # Check if it's a URL
                    if url.startswith(('http://', 'https://')) and not url.startswith('/'):
                        clean_urls.add(url)
                elif url and not url.startswith(('http://', 'https://')) and not url.startswith('/'):
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
            r'\b\w+\.(?:exe|bat|cmd|com|scr|pif|msi|jar)\b',  # Windows executables
            r'\b\w+\.(?:sh|bin|run|app|deb|rpm|pkg)\b',       # Unix/Linux executables
            r'\b\w+\.(?:apk|ipa)\b',                          # Mobile apps
            r'[C-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\.(?:exe|bat|cmd|com|scr|pif|msi)\b'  # Full Windows paths
        ]
        
        executables = set()
        for pattern in patterns:
            executables.update(re.findall(pattern, text, re.IGNORECASE))
        
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