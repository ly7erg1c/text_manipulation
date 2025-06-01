"""
CLI interface for IP address scanning functionality.

This module provides the command-line interface for bulk IP scanning
against threat intelligence services.
"""

import asyncio
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from ..core.ip_scanner import IPScanner
from ..core.config import APIConfig
from .display import Color, display_header, display_result


class IPScannerInterface:
    """CLI interface for IP scanning operations."""
    
    def __init__(self):
        """Initialize IP scanner interface."""
        self.scanner = IPScanner()
        self.config = APIConfig()
    
    def run(self) -> None:
        """Run the IP scanner interface."""
        display_header("IP Address Threat Intelligence Scanner")
        
        # Validate API keys
        valid, missing_keys = self.config.validate_api_keys()
        if not valid:
            print(f"\n{Color.RED}Missing API keys: {', '.join(missing_keys)}")
            print(f"Please set these environment variables or create a .env file{Color.RESET}")
            print("\nExample .env file:")
            print("VIRUSTOTAL_API_KEY=your_api_key_here")
            print("ABUSEIPDB_API_KEY=your_api_key_here")
            print("IPINFO_API_KEY=your_api_key_here  # Optional - works without key")
            return
        
        # Show API status
        print(f"\n{Color.GREEN}✓ Required API keys configured{Color.RESET}")
        if self.config.ipinfo_api_key:
            print(f"{Color.GREEN}✓ IPInfo API key configured (enhanced features){Color.RESET}")
        else:
            print(f"{Color.YELLOW}ℹ IPInfo using free tier (50k requests/month){Color.RESET}")
        
        # Get IP addresses to scan
        ip_addresses = self._get_ip_addresses()
        if not ip_addresses:
            print(f"\n{Color.RED}No IP addresses provided{Color.RESET}")
            return
        
        print(f"\n{Color.CYAN}Scanning {len(ip_addresses)} IP addresses...{Color.RESET}")
        
        # Run the scan
        results = asyncio.run(self.scanner.scan_ip_list(ip_addresses))
        
        # Display results
        self._display_scan_results(results)
        
        # Offer to export results
        if self._prompt_export():
            self._export_results()
    
    def _get_ip_addresses(self) -> List[str]:
        """
        Get IP addresses from user input.
        
        Returns:
            List of IP addresses to scan
        """
        print("\nHow would you like to input IP addresses?")
        print("1. Enter manually (comma-separated)")
        print("2. Load from file")
        print("3. Paste from clipboard")
        
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
        """Get IP addresses from manual input."""
        input_str = input("\nEnter IP addresses (comma-separated): ")
        ips = [ip.strip() for ip in input_str.split(",") if ip.strip()]
        return self._validate_ip_list(ips)
    
    def _load_from_file(self) -> List[str]:
        """Load IP addresses from file."""
        filepath = input("\nEnter file path: ").strip()
        try:
            with open(filepath, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            return self._validate_ip_list(ips)
        except Exception as e:
            print(f"{Color.RED}Error reading file: {e}{Color.RESET}")
            return []
    
    def _get_from_clipboard(self) -> List[str]:
        """Get IP addresses from clipboard."""
        try:
            import pyperclip
            text = pyperclip.paste()
            # Extract IPs using the existing NetworkExtractor
            from ..core.extractors import NetworkExtractor
            extractor = NetworkExtractor()
            ips = list(extractor.extract_ipv4(text))
            return self._validate_ip_list(ips)
        except Exception as e:
            print(f"{Color.RED}Error reading clipboard: {e}{Color.RESET}")
            return []
    
    def _validate_ip_list(self, ips: List[str]) -> List[str]:
        """Validate and deduplicate IP list."""
        # Remove duplicates while preserving order
        seen = set()
        valid_ips = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                valid_ips.append(ip)
        return valid_ips
    
    def _display_scan_results(self, results: List[dict]) -> None:
        """Display scan results in formatted output."""
        print(f"\n{Color.GREEN}=== Scan Results ==={Color.RESET}")
        
        for result in results:
            ip = result["ip"]
            print(f"\n{Color.CYAN}IP: {ip}{Color.RESET}")
            
            # Display IPInfo geolocation data first
            ipinfo = result.get("ipinfo")
            if ipinfo and "error" not in ipinfo:
                print(f"  {Color.BLUE}Location:{Color.RESET}")
                city = ipinfo.get("city", "Unknown")
                region = ipinfo.get("region", "Unknown")
                country_name = ipinfo.get("country_name", ipinfo.get("country", "Unknown"))
                print(f"    City: {city}, {region}, {country_name}")
                
                if ipinfo.get("latitude") and ipinfo.get("longitude"):
                    lat = ipinfo.get("latitude")
                    lon = ipinfo.get("longitude")
                    print(f"    Coordinates: {lat}, {lon}")
                
                timezone = ipinfo.get("timezone", "N/A")
                if timezone != "N/A":
                    print(f"    Timezone: {timezone}")
                
                organization = ipinfo.get("organization", "Unknown")
                print(f"    ISP/Org: {organization}")
                
                # Show special flags if present
                flags = []
                if ipinfo.get("is_vpn"):
                    flags.append("VPN")
                if ipinfo.get("is_proxy"):
                    flags.append("Proxy")
                if ipinfo.get("is_hosting"):
                    flags.append("Hosting")
                if ipinfo.get("is_mobile"):
                    flags.append("Mobile")
                
                if flags:
                    print(f"    Flags: {Color.YELLOW}{', '.join(flags)}{Color.RESET}")
            
            # Display VirusTotal results
            vt = result.get("virustotal")
            if vt and "error" not in vt:
                score = vt.get("reputation_score", "Unknown")
                color = Color.GREEN if score == "Clean" else Color.RED if score == "Malicious" else Color.YELLOW
                print(f"  VirusTotal: {color}{score}{Color.RESET}")
                stats = vt.get("reputation_stats", {})
                print(f"    Detections - Malicious: {stats.get('malicious', 0)}, "
                      f"Suspicious: {stats.get('suspicious', 0)}, "
                      f"Clean: {stats.get('harmless', 0)}")
            
            # Display AbuseIPDB results
            abuse = result.get("abuseipdb")
            if abuse and "error" not in abuse:
                confidence = abuse.get("abuse_confidence_score", 0)
                color = Color.GREEN if confidence < 25 else Color.RED if confidence > 75 else Color.YELLOW
                print(f"  AbuseIPDB: {color}Confidence Score: {confidence}%{Color.RESET}")
                print(f"    Reports: {abuse.get('total_reports', 0)} from "
                      f"{abuse.get('num_distinct_users', 0)} users")
                
                categories = abuse.get("abuse_categories", [])
                if categories:
                    print(f"    Categories: {', '.join(categories)}")
        
        # Display summary
        summary = self.scanner.get_summary_report()
        print(f"\n{Color.GREEN}=== Summary ==={Color.RESET}")
        print(f"Total Scanned: {summary['total_scanned']}")
        print(f"{Color.RED}Malicious: {summary['malicious_count']}{Color.RESET}")
        print(f"{Color.YELLOW}Suspicious: {summary['suspicious_count']}{Color.RESET}")
        print(f"{Color.GREEN}Clean: {summary['clean_count']}{Color.RESET}")
    
    def _prompt_export(self) -> bool:
        """Prompt user to export results."""
        response = input("\nExport results to JSON? (y/n): ").strip().lower()
        return response == 'y'
    
    def _export_results(self) -> None:
        """Export scan results to file."""
        filename = f"ip_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = Path(filename)
        
        try:
            self.scanner.export_results(filepath)
            print(f"{Color.GREEN}Results exported to: {filepath}{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}Error exporting results: {e}{Color.RESET}") 