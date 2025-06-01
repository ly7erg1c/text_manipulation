"""
Core extractor classes for different types of data.

This module contains classes for extracting various types of data from text:
- Hashes (SHA256, SHA1, MD5)
- Network data (IPv4 addresses, URLs)
- File references (executables)
- Text manipulation utilities
"""

import re
from typing import Set, List, Tuple


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
    
    @classmethod
    def defang_urls(cls, text: str) -> Set[str]:
        """
        Extract URLs and return them in defanged format (dots replaced with [.]).
        
        Args:
            text: The input text to search
            
        Returns:
            Set of unique defanged URLs found
        """
        urls = cls.extract_urls(text)
        return {url.replace('.', '[.]') for url in urls}


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