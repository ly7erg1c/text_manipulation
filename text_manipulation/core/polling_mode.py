"""
Clipboard polling mode for automatic threat intelligence analysis.

This module provides a background polling service that monitors the clipboard
for SHA hashes and IP addresses, automatically analyzing them through various
threat intelligence APIs and streaming results to the terminal.
"""

import asyncio
import time
from typing import Set, Dict, Any, Optional, List
from datetime import datetime
import pyperclip

from .extractors import HashExtractor, NetworkExtractor
from .api_clients.virustotal import VirusTotalClient
from .api_clients.abuseipdb import AbuseIPDBClient
from .api_clients.ipinfo import IPInfoClient
from .config import APIConfig


class ClipboardPoller:
    """
    Monitors clipboard and automatically analyzes detected IOCs.
    
    Watches clipboard for:
    - SHA256 hashes
    - SHA1 hashes 
    - MD5 hashes
    - IPv4 addresses
    - URLs
    
    Automatically performs threat intelligence lookups and streams results.
    """
    
    def __init__(self, poll_interval: float = 2.0):
        """
        Initialize clipboard poller.
        
        Args:
            poll_interval: How often to check clipboard (seconds)
        """
        self.poll_interval = poll_interval
        self.last_clipboard_content = ""
        self.processed_iocs = set()  # Track already processed IOCs
        self.is_running = False
        
        # Initialize extractors
        self.hash_extractor = HashExtractor()
        self.network_extractor = NetworkExtractor()
        
        # Initialize API clients
        self.config = APIConfig()
        self._setup_api_clients()
        
        # Statistics
        self.stats = {
            "start_time": None,
            "total_hashes_processed": 0,
            "total_ips_processed": 0,
            "total_urls_processed": 0,
            "malicious_hashes": 0,
            "malicious_ips": 0,
            "malicious_urls": 0,
            "polling_cycles": 0
        }
    
    def _setup_api_clients(self) -> None:
        """Set up API clients if keys are available."""
        self.virustotal_client = None
        self.abuseipdb_client = None
        self.ipinfo_client = None
        
        if self.config.virustotal_api_key:
            self.virustotal_client = VirusTotalClient(self.config.virustotal_api_key)
            
        if self.config.abuseipdb_api_key:
            self.abuseipdb_client = AbuseIPDBClient(self.config.abuseipdb_api_key)
        
        # IPInfo works with or without API key
        self.ipinfo_client = IPInfoClient(self.config.ipinfo_api_key)
    
    def start_polling(self) -> None:
        """Start the clipboard polling loop."""
        print("\n" + "=" * 80)
        print("             CLIPBOARD THREAT INTELLIGENCE MONITOR")
        print("=" * 80)
        print("\nMonitoring clipboard for SHA hashes, IP addresses, and URLs...")
        print("Press Ctrl+C to stop monitoring")
        print("\nConfiguration:")
        
        # Show API status
        api_status = []
        if self.virustotal_client:
            api_status.append("[CONFIGURED] VirusTotal")
        else:
            api_status.append("[NOT CONFIGURED] VirusTotal (required for hash/URL analysis)")
        
        if self.abuseipdb_client:
            api_status.append("[CONFIGURED] AbuseIPDB")
        else:
            api_status.append("[NOT CONFIGURED] AbuseIPDB")
        
        if self.ipinfo_client:
            api_status.append("[CONFIGURED] IPInfo")
        else:
            api_status.append("[NOT CONFIGURED] IPInfo")
        
        print(f"   APIs: {' | '.join(api_status)}")
        print(f"   Poll interval: {self.poll_interval}s")
        print("\n" + "-" * 80)
        
        # Initialize last_clipboard_content with current clipboard to avoid processing initial content
        try:
            self.last_clipboard_content = pyperclip.paste()
        except Exception:
            self.last_clipboard_content = ""
        
        self.is_running = True
        self.stats["start_time"] = datetime.now()
        
        try:
            asyncio.run(self._polling_loop())
        except KeyboardInterrupt:
            self._show_session_summary()
            print("\nMonitoring stopped by user")
    
    async def _polling_loop(self) -> None:
        """Main polling loop."""
        while self.is_running:
            try:
                # Get current clipboard content
                current_content = pyperclip.paste()
                
                if current_content != self.last_clipboard_content and current_content.strip():
                    self.last_clipboard_content = current_content
                    await self._process_clipboard_content(current_content)
                
                self.stats["polling_cycles"] += 1
                await asyncio.sleep(self.poll_interval)
                
            except Exception as e:
                print(f"\nError in polling loop: {e}")
                await asyncio.sleep(self.poll_interval)
    
    async def _process_clipboard_content(self, content: str) -> None:
        """
        Process clipboard content for IOCs and analyze them.
        
        Args:
            content: Current clipboard content
        """
        # Extract IOCs first
        sha256_hashes = self.hash_extractor.extract_sha256(content)
        sha1_hashes = self.hash_extractor.extract_sha1(content)
        md5_hashes = self.hash_extractor.extract_md5(content)
        ip_addresses = self.network_extractor.extract_ipv4(content)
        urls = self.network_extractor.extract_urls(content)
        
        # Combine all hashes
        all_hashes = sha256_hashes | sha1_hashes | md5_hashes
        
        # Filter out already processed IOCs
        new_hashes = all_hashes - self.processed_iocs
        new_ips = ip_addresses - self.processed_iocs
        new_urls = urls - self.processed_iocs
        
        # Only show message and process if there are new IOCs
        if not new_hashes and not new_ips and not new_urls:
            return  # Silent return, no message
        
        # Now show message since we have new IOCs
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] New IOCs detected in clipboard...")
        
        # Process new IOCs
        tasks = []
        
        if new_hashes:
            print(f"   Found {len(new_hashes)} new hash(es)")
            for hash_val in new_hashes:
                tasks.append(self._analyze_hash(hash_val))
        
        if new_ips:
            print(f"   Found {len(new_ips)} new IP address(es)")
            for ip in new_ips:
                tasks.append(self._analyze_ip(ip))
        
        if new_urls:
            print(f"   Found {len(new_urls)} new URL(s)")
            for url in new_urls:
                tasks.append(self._analyze_url(url))
        
        # Process all IOCs concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Update processed IOCs
        self.processed_iocs.update(new_hashes)
        self.processed_iocs.update(new_ips)
        self.processed_iocs.update(new_urls)
    
    async def _analyze_hash(self, hash_value: str) -> None:
        """
        Analyze a file hash using threat intelligence APIs.
        
        Args:
            hash_value: Hash to analyze
        """
        self.stats["total_hashes_processed"] += 1
        
        print(f"\nHASH ANALYSIS: {hash_value}")
        print("   " + "─" * 60)
        
        if not self.virustotal_client:
            print("   WARNING: VirusTotal API key required for hash analysis")
            return
        
        try:
            result = await self.virustotal_client.check_hash_reputation(hash_value)
            self._display_hash_result(result)
        except Exception as e:
            print(f"   ERROR: Error analyzing hash: {e}")
    
    async def _analyze_ip(self, ip_address: str) -> None:
        """
        Analyze an IP address using threat intelligence APIs.
        
        Args:
            ip_address: IP address to analyze
        """
        self.stats["total_ips_processed"] += 1
        
        print(f"\nIP ANALYSIS: {ip_address}")
        print("   " + "─" * 60)
        
        # Run all available IP checks in parallel
        tasks = []
        
        if self.virustotal_client:
            tasks.append(("VirusTotal", self.virustotal_client.check_ip_reputation(ip_address)))
        
        if self.abuseipdb_client:
            tasks.append(("AbuseIPDB", self.abuseipdb_client.check_ip_abuse(ip_address)))
        
        if self.ipinfo_client:
            tasks.append(("IPInfo", self.ipinfo_client.get_ip_info(ip_address)))
        
        if not tasks:
            print("   WARNING: No API keys configured for IP analysis")
            return
        
        try:
            # Execute all tasks
            service_names = [task[0] for task in tasks]
            service_tasks = [task[1] for task in tasks]
            results = await asyncio.gather(*service_tasks, return_exceptions=True)
            
            # Display results
            for service_name, result in zip(service_names, results):
                if isinstance(result, Exception):
                    print(f"   ERROR {service_name}: {result}")
                else:
                    self._display_ip_result(service_name, result, ip_address)
                    
        except Exception as e:
            print(f"   ERROR: Error analyzing IP: {e}")
    
    async def _analyze_url(self, url: str) -> None:
        """
        Analyze a URL using threat intelligence APIs.
        
        Args:
            url: URL to analyze
        """
        self.stats["total_urls_processed"] += 1
        
        print(f"\nURL ANALYSIS: {url}")
        print("   " + "─" * 60)
        
        if not self.virustotal_client:
            print("   WARNING: VirusTotal API key required for URL analysis")
            return
        
        try:
            result = await self.virustotal_client.check_url_reputation(url)
            self._display_url_result(result)
        except Exception as e:
            print(f"   ERROR: Error analyzing URL: {e}")
    
    def _display_hash_result(self, result: Dict[str, Any]) -> None:
        """
        Display hash analysis results in a clean format.
        
        Args:
            result: Hash analysis result from VirusTotal
        """
        if "error" in result:
            print(f"   ERROR: {result['error']}")
            return
        
        reputation = result.get("reputation_score", "Unknown")
        stats = result.get("reputation_stats", {})
        
        # Choose appropriate status indicator
        if reputation == "Malicious":
            status_indicator = "[MALICIOUS]"
            self.stats["malicious_hashes"] += 1
        elif reputation == "Suspicious":
            status_indicator = "[SUSPICIOUS]"
        else:
            status_indicator = "[CLEAN]"
        
        print(f"   Status: {status_indicator} {reputation}")
        print(f"   Detections: {stats.get('malicious', 0)}/{sum(stats.values())} engines")
        
        if result.get("file_type"):
            print(f"   Type: {result['file_type']}")
        
        if result.get("meaningful_name"):
            print(f"   Name: {result['meaningful_name']}")
        elif result.get("names"):
            print(f"   Names: {', '.join(result['names'][:3])}")
        
        if result.get("file_size"):
            size_mb = result["file_size"] / (1024 * 1024)
            if size_mb > 1:
                print(f"   Size: {size_mb:.2f} MB")
            else:
                size_kb = result["file_size"] / 1024
                print(f"   Size: {size_kb:.2f} KB")
    
    def _display_ip_result(self, service: str, result: Dict[str, Any], ip_address: str) -> None:
        """
        Display IP analysis results in a clean format.
        
        Args:
            service: Name of the service that provided the result
            result: Analysis result
            ip_address: IP address being analyzed
        """
        if "error" in result:
            print(f"   ERROR {service}: {result['error']}")
            return
        
        print(f"   {service}:")
        
        if service == "VirusTotal":
            reputation = result.get("reputation_score", "Unknown")
            stats = result.get("reputation_stats", {})
            
            if reputation == "Malicious":
                print(f"      Status: [MALICIOUS] {reputation}")
                self.stats["malicious_ips"] += 1
            elif reputation == "Suspicious":
                print(f"      Status: [SUSPICIOUS] {reputation}")
            else:
                print(f"      Status: [CLEAN] {reputation}")
            
            print(f"      Detections: {stats.get('malicious', 0)}/{sum(stats.values())} engines")
            
            if result.get("country"):
                print(f"      Country: {result['country']}")
            if result.get("owner"):
                print(f"      Owner: {result['owner']}")
        
        elif service == "AbuseIPDB":
            confidence = result.get("abuse_confidence_score", 0)
            
            if confidence > 75:
                print(f"      Abuse Confidence: [HIGH] {confidence}%")
                if ip_address not in [result.get("ip") for result in [r for r in [result] if r.get("ip")]]:
                    self.stats["malicious_ips"] += 1
            elif confidence > 25:
                print(f"      Abuse Confidence: [MEDIUM] {confidence}%")
            else:
                print(f"      Abuse Confidence: [LOW] {confidence}%")
            
            if result.get("country_code") and result.get("country_code") != "Unknown":
                print(f"      Country: {result['country_code']}")
            if result.get("usage_type") and result.get("usage_type") != "Unknown":
                print(f"      Usage: {result['usage_type']}")
            if result.get("total_reports", 0) > 0:
                print(f"      Total Reports: {result['total_reports']}")
        
        elif service == "IPInfo":
            if result.get("country"):
                print(f"      Location: {result.get('city', 'Unknown')}, {result['country']}")
            if result.get("org"):
                print(f"      Organization: {result['org']}")
            if result.get("timezone"):
                print(f"      Timezone: {result['timezone']}")
    
    def _display_url_result(self, result: Dict[str, Any]) -> None:
        """
        Display URL analysis results in a clean format.
        
        Args:
            result: URL analysis result from VirusTotal
        """
        if "error" in result:
            print(f"   ERROR: {result['error']}")
            return
        
        reputation = result.get("reputation_score", "Unknown")
        stats = result.get("reputation_stats", {})
        
        # Choose appropriate status indicator
        if reputation == "Malicious":
            status_indicator = "[MALICIOUS]"
            self.stats["malicious_urls"] += 1
        elif reputation == "Suspicious":
            status_indicator = "[SUSPICIOUS]"
        else:
            status_indicator = "[CLEAN]"
        
        print(f"   Status: {status_indicator} {reputation}")
        print(f"   Detections: {stats.get('malicious', 0)}/{sum(stats.values())} engines")
        
        if result.get("title") and result.get("title") != "Unknown":
            print(f"   Title: {result['title']}")
        
        if result.get("final_url") and result.get("final_url") != result.get("url"):
            print(f"   Final URL: {result['final_url']}")
        
        if result.get("categories"):
            categories = list(result["categories"].keys())[:3]  # Show first 3 categories
            if categories:
                print(f"   Categories: {', '.join(categories)}")
        
        if result.get("threat_names"):
            threat_names = result["threat_names"][:3]  # Show first 3 threat names
            if threat_names:
                print(f"   Threats: {', '.join(threat_names)}")
    
    def _show_session_summary(self) -> None:
        """Display session summary statistics."""
        if not self.stats["start_time"]:
            return
        
        duration = datetime.now() - self.stats["start_time"]
        hours = int(duration.total_seconds() // 3600)
        minutes = int((duration.total_seconds() % 3600) // 60)
        seconds = int(duration.total_seconds() % 60)
        
        print("\n" + "=" * 80)
        print("                        SESSION SUMMARY")
        print("=" * 80)
        print(f"Duration: {hours:02d}:{minutes:02d}:{seconds:02d}")
        print(f"Polling cycles: {self.stats['polling_cycles']}")
        print(f"Hashes analyzed: {self.stats['total_hashes_processed']}")
        print(f"IPs analyzed: {self.stats['total_ips_processed']}")
        print(f"Malicious hashes: {self.stats['malicious_hashes']}")
        print(f"Malicious IPs: {self.stats['malicious_ips']}")
        print(f"URLs analyzed: {self.stats['total_urls_processed']}")
        print(f"Malicious URLs: {self.stats['malicious_urls']}")
        print("=" * 80) 