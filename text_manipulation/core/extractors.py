"""
Core extractor classes for different types of data.

This module contains classes for extracting various types of data from text:
- Hashes (SHA256, SHA1, MD5)
- Network data (IPv4 addresses, URLs, defanged formats)
- File references (executables)
- Text manipulation utilities
"""

import re
from typing import Set, List, Tuple, Dict


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
            defanged = url.replace('.', '[.]')
            defanged = defanged.replace('http://', 'hxxp://')
            defanged = defanged.replace('https://', 'hxxps://')
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
        unfanged = defanged_url.replace('[.]', '.')
        unfanged = unfanged.replace('hxxp://', 'http://')
        unfanged = unfanged.replace('hxxps://', 'https://')
        return unfanged
    
    @classmethod
    def extract_all_ips_and_urls(cls, text: str) -> Dict[str, Set[str]]:
        """
        Extract all IP addresses and URLs (both normal and defanged formats).
        
        Args:
            text: The input text to search
            
        Returns:
            Dictionary with extracted IOCs categorized by type
        """
        return {
            'ipv4': cls.extract_ipv4(text),
            'defanged_ipv4': cls.extract_defanged_ipv4(text),
            'urls': cls.extract_urls(text),
            'defanged_urls': cls.extract_defanged_urls(text)
        }


class FileExtractor:
    """Extracts file references from text."""
    
    @staticmethod
    def extract_executables(text: str) -> Set[str]:
        """
        Extract executable file references from text.
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique executable file references found
        """
        pattern = r"([^,\s]+\.exe|[^,\s]+\.bat|[^,\s]+\.cmd|[^,\s]+\.sh|[^,\s]+\.bin)\b"
        return set(re.findall(pattern, text))


class TextManipulator:
    """Provides text manipulation utilities."""
    
    @staticmethod
    def newline_to_space(text: str) -> str:
        """
        Convert newlines to spaces and strip whitespace.
        
        Args:
            text: The input text to transform
            
        Returns:
            Text with newlines replaced by spaces
        """
        return text.replace('\n', ' ').strip()
    
    @staticmethod
    def remove_blank_lines(text: str) -> str:
        """
        Remove blank lines from text.
        
        Args:
            text: The input text to clean
            
        Returns:
            Text with blank lines removed
        """
        return "\n".join([line for line in text.split('\n') if line.strip()])


class DefangUtility:
    """Utility class for defanging and unfanging operations."""
    
    @staticmethod
    def defang_text(text: str) -> str:
        """
        Defang all URLs and IP addresses in text.
        
        Args:
            text: The input text to defang
            
        Returns:
            Text with all URLs and IPs defanged
        """
        # First defang URLs
        defanged_text = text
        defanged_text = defanged_text.replace('http://', 'hxxp://')
        defanged_text = defanged_text.replace('https://', 'hxxps://')
        
        # Then defang IP addresses (replace dots with [.])
        ip_pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        def replace_ip_dots(match):
            return match.group(0).replace('.', '[.]')
        
        defanged_text = re.sub(ip_pattern, replace_ip_dots, defanged_text)
        
        # Finally, defang general domains (replace dots with [.])
        domain_pattern = r'\b[a-zA-Z0-9-]+\.(?:[a-zA-Z]{2,}|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b'
        
        def replace_domain_dots(match):
            domain = match.group(0)
            # Don't defang if it's already defanged or if it's an IP
            if '[.]' in domain or re.match(ip_pattern, domain):
                return domain
            return domain.replace('.', '[.]')
        
        defanged_text = re.sub(domain_pattern, replace_domain_dots, defanged_text)
        
        return defanged_text
    
    @staticmethod
    def unfang_text(text: str) -> str:
        """
        Unfang all defanged URLs and IP addresses in text.
        
        Args:
            text: The input text to unfang
            
        Returns:
            Text with all defanged URLs and IPs restored to normal format
        """
        unfanged_text = text
        unfanged_text = unfanged_text.replace('hxxp://', 'http://')
        unfanged_text = unfanged_text.replace('hxxps://', 'https://')
        unfanged_text = unfanged_text.replace('[.]', '.')
        
        return unfanged_text 