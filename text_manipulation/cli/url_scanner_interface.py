"""
CLI interface for URL scanning functionality.

This module provides the command-line interface for bulk URL scanning
against VirusTotal threat intelligence service.
"""

import asyncio
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from ..core.api_clients.virustotal import VirusTotalClient
from ..core.extractors import NetworkExtractor
from ..core.config import APIConfig
from .display import Color, display_header, display_result


class URLScannerInterface:
    """CLI interface for URL scanning operations."""
    
    def __init__(self):
        """Initialize URL scanner interface."""
        self.config = APIConfig()
        self.virustotal_client = None
        if self.config.virustotal_api_key:
            self.virustotal_client = VirusTotalClient(self.config.virustotal_api_key)
        self.scan_results = []
    
    def run(self) -> None:
        """Run the URL scanner interface."""
        display_header("URL Threat Intelligence Scanner")
        
        # Validate API keys
        if not self.config.virustotal_api_key:
            print(f"\n{Color.RED}Missing VirusTotal API key")
            print(f"Please set VIRUSTOTAL_API_KEY environment variable or create a .env file{Color.RESET}")
            print("\nExample .env file:")
            print("VIRUSTOTAL_API_KEY=your_api_key_here")
            return
        
        # Show API status
        print(f"\n{Color.GREEN}✓ VirusTotal API key configured{Color.RESET}")
        
        # Get URLs to scan
        urls = self._get_urls()
        if not urls:
            print(f"\n{Color.RED}No URLs provided{Color.RESET}")
            return
        
        print(f"\n{Color.CYAN}Scanning {len(urls)} URL(s)...{Color.RESET}")
        
        # Run the scan
        results = asyncio.run(self._scan_url_list(urls))
        
        # Display results
        self._display_scan_results(results)
        
        # Offer to export results
        if self._prompt_export():
            self._export_results()
    
    async def _scan_url_list(self, urls: List[str]) -> List[dict]:
        """
        Scan a list of URLs.
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            List of scan results
        """
        results = []
        
        for url in urls:
            print(f"  Scanning: {url[:60]}{'...' if len(url) > 60 else ''}")
            result = await self._scan_single_url(url)
            results.append(result)
            
            # Add delay between requests to respect rate limits
            if len(urls) > 1:
                await asyncio.sleep(1)
        
        self.scan_results = results
        return results
    
    async def _scan_single_url(self, url: str) -> dict:
        """
        Scan a single URL.
        
        Args:
            url: URL to scan
            
        Returns:
            Scan result dictionary
        """
        result = {
            "url": url,
            "scan_timestamp": datetime.now().isoformat(),
            "virustotal": None
        }
        
        try:
            vt_result = await self.virustotal_client.check_url_reputation(url)
            result["virustotal"] = vt_result
        except Exception as e:
            result["virustotal"] = {"error": str(e)}
        
        return result
    
    def _get_urls(self) -> List[str]:
        """
        Get URLs from user input.
        
        Returns:
            List of URLs to scan
        """
        print("\nHow would you like to input URLs?")
        print("1. Enter manually (one per line or comma-separated)")
        print("2. Load from file")
        print("3. Extract from clipboard")
        
        choice = input("\nChoice (1-3): ").strip()
        
        if choice == "1":
            return self._get_manual_input()
        elif choice == "2":
            return self._load_from_file()
        elif choice == "3":
            return self._get_from_clipboard()
        else:
            return []
    
    def _get_manual_input(self) -> List[str]:
        """Get URLs from manual input."""
        print("\nEnter URLs (press Enter twice when done):")
        urls = []
        while True:
            line = input().strip()
            if not line:
                break
            # Handle comma-separated URLs on a single line
            if ',' in line:
                urls.extend([url.strip() for url in line.split(',') if url.strip()])
            else:
                urls.append(line)
        
        return self._validate_url_list(urls)
    
    def _load_from_file(self) -> List[str]:
        """Load URLs from file."""
        filepath = input("\nEnter file path: ").strip()
        try:
            with open(filepath, 'r') as f:
                urls = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip comments
                        urls.append(line)
            return self._validate_url_list(urls)
        except Exception as e:
            print(f"{Color.RED}Error reading file: {e}{Color.RESET}")
            return []
    
    def _get_from_clipboard(self) -> List[str]:
        """Get URLs from clipboard."""
        try:
            import pyperclip
            text = pyperclip.paste()
            # Extract URLs using the existing NetworkExtractor
            extractor = NetworkExtractor()
            urls = list(extractor.extract_urls(text))
            return self._validate_url_list(urls)
        except Exception as e:
            print(f"{Color.RED}Error reading clipboard: {e}{Color.RESET}")
            return []
    
    def _validate_url_list(self, urls: List[str]) -> List[str]:
        """Validate and deduplicate URL list."""
        # Remove duplicates while preserving order
        seen = set()
        valid_urls = []
        for url in urls:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            if url not in seen:
                seen.add(url)
                valid_urls.append(url)
        
        return valid_urls
    
    def _display_scan_results(self, results: List[dict]) -> None:
        """Display scan results in formatted output."""
        print(f"\n{Color.GREEN}=== URL Scan Results ==={Color.RESET}")
        
        for result in results:
            url = result["url"]
            print(f"\n{Color.CYAN}URL: {url}{Color.RESET}")
            
            # Display VirusTotal results
            vt = result.get("virustotal")
            if vt and "error" not in vt:
                score = vt.get("reputation_score", "Unknown")
                color = Color.GREEN if score == "Clean" else Color.RED if score == "Malicious" else Color.YELLOW
                print(f"  VirusTotal: {color}{score}{Color.RESET}")
                
                stats = vt.get("reputation_stats", {})
                total_engines = sum(stats.values())
                print(f"    Detections: {stats.get('malicious', 0)}/{total_engines} engines")
                print(f"    Breakdown - Malicious: {stats.get('malicious', 0)}, "
                      f"Suspicious: {stats.get('suspicious', 0)}, "
                      f"Clean: {stats.get('harmless', 0)}, "
                      f"Undetected: {stats.get('undetected', 0)}")
                
                if vt.get("title") and vt.get("title") != "Unknown":
                    print(f"    Title: {vt['title']}")
                
                if vt.get("final_url") and vt.get("final_url") != vt.get("url"):
                    print(f"    Final URL: {vt['final_url']}")
                
                if vt.get("categories"):
                    categories = list(vt["categories"].keys())[:5]  # Show first 5 categories
                    if categories:
                        print(f"    Categories: {', '.join(categories)}")
                
                if vt.get("threat_names"):
                    threat_names = vt["threat_names"][:3]  # Show first 3 threat names
                    if threat_names:
                        print(f"    Threats: {Color.RED}{', '.join(threat_names)}{Color.RESET}")
            else:
                error_msg = vt.get("error", "Unknown error") if vt else "No result"
                print(f"  VirusTotal: {Color.RED}Error - {error_msg}{Color.RESET}")
        
        # Display summary
        self._display_summary(results)
    
    def _display_summary(self, results: List[dict]) -> None:
        """Display scan summary."""
        total_urls = len(results)
        malicious_urls = []
        suspicious_urls = []
        clean_urls = []
        error_urls = []
        
        for result in results:
            url = result["url"]
            vt_result = result.get("virustotal", {})
            
            if "error" in vt_result:
                error_urls.append(url)
            else:
                score = vt_result.get("reputation_score", "Unknown")
                if score == "Malicious":
                    malicious_urls.append(url)
                elif score == "Suspicious":
                    suspicious_urls.append(url)
                elif score == "Clean":
                    clean_urls.append(url)
        
        print(f"\n{Color.GREEN}=== Summary ==={Color.RESET}")
        print(f"Total URLs scanned: {total_urls}")
        print(f"{Color.RED}Malicious: {len(malicious_urls)}{Color.RESET}")
        print(f"{Color.YELLOW}Suspicious: {len(suspicious_urls)}{Color.RESET}")
        print(f"{Color.GREEN}Clean: {len(clean_urls)}{Color.RESET}")
        print(f"Errors: {len(error_urls)}")
        
        if malicious_urls:
            print(f"\n{Color.RED}Malicious URLs:{Color.RESET}")
            for url in malicious_urls:
                print(f"  - {url}")
        
        if suspicious_urls:
            print(f"\n{Color.YELLOW}Suspicious URLs:{Color.RESET}")
            for url in suspicious_urls:
                print(f"  - {url}")
    
    def _prompt_export(self) -> bool:
        """Prompt user to export results."""
        choice = input(f"\n{Color.CYAN}Export results to file? (y/n): {Color.RESET}").strip().lower()
        return choice in ['y', 'yes']
    
    def _export_results(self) -> None:
        """Export scan results to JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"url_scan_results_{timestamp}.json"
        
        try:
            import json
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=2, default=str)
            print(f"{Color.GREEN}Results exported to: {filename}{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}Error exporting results: {e}{Color.RESET}") 