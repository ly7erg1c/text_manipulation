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
from ..cli.display import Color


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
    
    def __init__(self, poll_interval: float = 2.0, limit_poll: int = 1):
        """
        Initialize clipboard poller.
        
        Args:
            poll_interval: How often to check clipboard (seconds)
            limit_poll: Maximum number of lines to scan from clipboard (default: 1)
        """
        self.poll_interval = poll_interval
        self.limit_poll = limit_poll
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
        print(f"   Scan limit: {'First line only' if self.limit_poll == 1 else f'First {self.limit_poll} lines'}")
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
        # Limit content to specified number of lines
        lines = content.split('\n')
        if self.limit_poll == 1:
            # Only process the first line
            content_to_process = lines[0] if lines else ""
        else:
            # Process up to limit_poll lines
            content_to_process = '\n'.join(lines[:self.limit_poll])
        
        # Extract IOCs from the limited content (including defanged ones)
        sha256_hashes = self.hash_extractor.extract_sha256(content_to_process)
        sha1_hashes = self.hash_extractor.extract_sha1(content_to_process)
        md5_hashes = self.hash_extractor.extract_md5(content_to_process)
        
        # Extract both normal and defanged IP addresses
        ip_addresses = self.network_extractor.extract_ipv4(content_to_process)
        defanged_ips = self.network_extractor.extract_defanged_ipv4(content_to_process)
        
        # Extract both normal and defanged URLs
        urls = self.network_extractor.extract_urls(content_to_process)
        defanged_urls = self.network_extractor.extract_defanged_urls(content_to_process)
        
        # Unfang defanged IOCs for analysis and tracking
        unfanged_ips = {self.network_extractor.unfang_ipv4(ip) for ip in defanged_ips}
        unfanged_urls = {self.network_extractor.unfang_url(url) for url in defanged_urls}
        
        # Check if any unfanged "URLs" are actually IP addresses and reclassify them
        actual_unfanged_urls = set()
        additional_unfanged_ips = set()
        
        for unfanged_url in unfanged_urls:
            # Check if this unfanged "URL" is actually an IP address
            if self.network_extractor.extract_ipv4(unfanged_url):
                additional_unfanged_ips.add(unfanged_url)
            else:
                actual_unfanged_urls.add(unfanged_url)
        
        # Combine all similar IOCs (use unfanged versions for processing)
        all_hashes = sha256_hashes | sha1_hashes | md5_hashes
        all_ips = ip_addresses | unfanged_ips | additional_unfanged_ips
        all_urls = urls | actual_unfanged_urls
        
        # Filter out already processed IOCs
        new_hashes = all_hashes - self.processed_iocs
        new_ips = all_ips - self.processed_iocs
        new_urls = all_urls - self.processed_iocs
        
        # Only show message and process if there are new IOCs
        if not new_hashes and not new_ips and not new_urls:
            return  # Silent return, no message
        
        # Now show message since we have new IOCs
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"\n┌─ [{timestamp}] New IOCs detected in clipboard")
        
        # Show detection details
        if defanged_ips:
            print(f"├─ Found {len(defanged_ips)} defanged IP(s)")
        if defanged_urls:
            print(f"├─ Found {len(defanged_urls)} defanged URL(s)")
        
        # Process new IOCs
        tasks = []
        
        if new_hashes:
            print(f"├─ Found {len(new_hashes)} new hash(es)")
            for hash_val in new_hashes:
                tasks.append(self._analyze_hash(hash_val))
        
        if new_ips:
            print(f"└─ Processing {len(new_ips)} IP address(es)")
            for ip in new_ips:
                # Check if this IP was originally defanged (either as IP or misclassified as URL)
                original_defanged = None
                
                # First check defanged IPs
                for defanged_ip in defanged_ips:
                    if self.network_extractor.unfang_ipv4(defanged_ip) == ip:
                        original_defanged = defanged_ip
                        break
                
                # If not found, check defanged URLs that were reclassified as IPs
                if not original_defanged:
                    for defanged_url in defanged_urls:
                        if self.network_extractor.unfang_url(defanged_url) == ip:
                            original_defanged = defanged_url
                            break
                
                tasks.append(self._analyze_ip(ip, original_defanged))
        
        if new_urls:
            print(f"└─ Processing {len(new_urls)} URL(s)")
            for url in new_urls:
                # Check if this URL was originally defanged
                original_defanged = None
                for defanged_url in defanged_urls:
                    if self.network_extractor.unfang_url(defanged_url) == url:
                        original_defanged = defanged_url
                        break
                tasks.append(self._analyze_url(url, original_defanged))
        
        # Process all IOCs concurrently
        if tasks:
            print()  # Add space before results
            
            # Track session stats for this batch
            session_abuse_count = 0
            
            # Analyze IPs and count abuse cases for this session
            for ip in new_ips:
                # This would be done in the actual analysis, but for summary we need a simpler approach
                pass
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Show quick summary if we processed multiple IPs
            if len(new_ips) > 1:
                print(f"┌─ Summary: Processed {len(new_ips)} IP addresses")
                print("└─" + "─" * 35)
        
        # Update processed IOCs (track unfanged versions)
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
    
    async def _analyze_ip(self, ip_address: str, original_defanged: Optional[str] = None) -> None:
        """
        Analyze an IP address using threat intelligence APIs.
        
        Args:
            ip_address: IP address to analyze
            original_defanged: Original defanged IP address
        """
        self.stats["total_ips_processed"] += 1
        
        # Run all available IP checks in parallel
        tasks = []
        
        if self.virustotal_client:
            tasks.append(("VirusTotal", self.virustotal_client.check_ip_reputation(ip_address)))
        
        if self.abuseipdb_client:
            tasks.append(("AbuseIPDB", self.abuseipdb_client.check_ip_abuse(ip_address)))
        
        if self.ipinfo_client:
            tasks.append(("IPInfo", self.ipinfo_client.get_ip_info(ip_address)))
        
        if not tasks:
            print(f"🔍 {ip_address} - No API keys configured")
            return
        
        try:
            # Execute all tasks
            service_names = [task[0] for task in tasks]
            service_tasks = [task[1] for task in tasks]
            results = await asyncio.gather(*service_tasks, return_exceptions=True)
            
            # Calculate overall status based on detections
            total_detections = 0
            vt_detections = 0
            abuse_confidence = 0
            
            for service_name, result in zip(service_names, results):
                if not isinstance(result, Exception):
                    if service_name == "VirusTotal" and "reputation_stats" in result:
                        vt_detections = result.get("reputation_stats", {}).get('malicious', 0)
                        total_detections += vt_detections
                    elif service_name == "AbuseIPDB" and "abuse_confidence_score" in result:
                        abuse_confidence = result.get("abuse_confidence_score", 0)
                        # Consider high confidence as additional "detections"
                        if abuse_confidence > 75:
                            total_detections += 2
                        elif abuse_confidence > 25:
                            total_detections += 1
            
            # Determine overall status and icon
            if total_detections >= 3:
                status_icon = "🚨"
                overall_status = f"{Color.RED}ABUSE{Color.RESET}"
                self.stats["malicious_ips"] += 1
            elif total_detections >= 1:
                status_icon = "⚠️ "
                overall_status = f"{Color.YELLOW}Possible Abuse{Color.RESET}"
            else:
                status_icon = "✅"
                overall_status = f"{Color.GREEN}CLEAN{Color.RESET}"
            
            # Display compact header
            defang_info = f" (from {original_defanged})" if original_defanged else ""
            print(f"{status_icon} {ip_address} - {overall_status}{defang_info}")
            
            # Display compact results
            for service_name, result in zip(service_names, results):
                if isinstance(result, Exception):
                    print(f"   {service_name}: {Color.RED}Error{Color.RESET}")
                else:
                    self._display_ip_result_compact(service_name, result)
            
            # Shorter separator
            print("─" * 40)
                    
        except Exception as e:
            print(f"🔍 {ip_address} - {Color.RED}Analysis failed{Color.RESET}")
            print("─" * 40)
    
    async def _analyze_url(self, url: str, original_defanged: Optional[str] = None) -> None:
        """
        Analyze a URL using threat intelligence APIs.
        
        Args:
            url: URL to analyze
            original_defanged: Original defanged URL
        """
        self.stats["total_urls_processed"] += 1
        
        print(f"\nURL ANALYSIS: {url}")
        if original_defanged:
            print(f"   (Original defanged format: {original_defanged})")
        print("   " + "─" * 60)
        
        if not self.virustotal_client:
            print("   WARNING: VirusTotal API key required for URL analysis")
            return
        
        try:
            result = await self.virustotal_client.check_url_reputation(url)
            self._display_url_result(result, original_defanged)
        except Exception as e:
            print(f"   ERROR: Error analyzing URL: {e}")
    
    def _display_hash_result(self, result: Dict[str, Any]) -> None:
        """
        Display hash analysis results in a clean format.
        
        Args:
            result: Hash analysis result from VirusTotal
        """
        if "error" in result:
            print(f"   {Color.RED}ERROR: {result['error']}{Color.RESET}")
            return
        
        reputation = result.get("reputation_score", "Unknown")
        stats = result.get("reputation_stats", {})
        malicious_count = stats.get('malicious', 0)
        total_count = sum(stats.values()) if stats else 0
        
        # Choose appropriate status indicator and color based on maliciousness
        if reputation == "Malicious":
            if malicious_count >= 10:
                status_indicator = f"{Color.RED}[MALICIOUS]{Color.RESET}"
            elif malicious_count >= 5:
                status_indicator = f"{Color.YELLOW}[MALICIOUS]{Color.RESET}"
            else:
                status_indicator = f"{Color.YELLOW}[MALICIOUS]{Color.RESET}"
            self.stats["malicious_hashes"] += 1
        elif reputation == "Suspicious":
            if malicious_count >= 3:
                status_indicator = f"{Color.YELLOW}[SUSPICIOUS]{Color.RESET}"
            else:
                status_indicator = f"{Color.CYAN}[SUSPICIOUS]{Color.RESET}"
        else:
            status_indicator = f"{Color.GREEN}[CLEAN]{Color.RESET}"
        
        print(f"   Status: {status_indicator} {reputation}")
        
        # Color the detection count based on threat level
        if malicious_count == 0:
            detection_color = Color.GREEN
        elif malicious_count <= 3:
            detection_color = Color.YELLOW
        else:
            detection_color = Color.RED
        
        print(f"   Detections: {detection_color}{malicious_count}/{total_count}{Color.RESET} engines")
        
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
    
    def _display_ip_result_compact(self, service: str, result: Dict[str, Any]) -> None:
        """
        Display IP analysis results in a compact single-line format.
        
        Args:
            service: Name of the service that provided the result
            result: Analysis result
        """
        if "error" in result:
            print(f"   {service}: {Color.RED}Error{Color.RESET}")
            return
        
        if service == "VirusTotal":
            malicious_count = result.get("reputation_stats", {}).get('malicious', 0)
            total_count = sum(result.get("reputation_stats", {}).values()) or 0
            
            # Compact status with color
            if malicious_count == 0:
                status_color = Color.GREEN
                status_text = "Clean"
            elif malicious_count <= 3:
                status_color = Color.YELLOW
                status_text = "Suspicious"
            else:
                status_color = Color.RED
                status_text = "Malicious"
            
            # Build compact info
            info_parts = [f"{status_color}{malicious_count}/{total_count}{Color.RESET}"]
            
            if result.get("country"):
                info_parts.append(result['country'])
            
            # Abbreviate common ASN names
            if result.get("owner"):
                owner = result['owner']
                owner = owner.replace("DIGITALOCEAN-ASN", "DigitalOcean")
                owner = owner.replace("GOOGLE-CLOUD-PLATFORM", "Google Cloud")
                owner = owner.replace("AS-COLOCROSSING", "ColoCrossing")
                owner = owner.replace("UNIFIEDLAYER-AS-1", "UnifiedLayer")
                owner = owner.replace("Data Center/Web Hosting/Transit", "Hosting")
                info_parts.append(owner[:20])  # Limit length
            
            print(f"   VT: {' | '.join(info_parts)}")
        
        elif service == "AbuseIPDB":
            confidence = result.get("abuse_confidence_score", 0)
            reports = result.get("total_reports", 0)
            
            # Compact confidence display
            if confidence > 75:
                conf_color = Color.RED
            elif confidence > 25:
                conf_color = Color.YELLOW
            else:
                conf_color = Color.GREEN
            
            info_parts = [f"{conf_color}{confidence}%{Color.RESET}"]
            
            if reports > 0:
                if reports > 100:
                    reports_color = Color.RED
                elif reports > 10:
                    reports_color = Color.YELLOW
                else:
                    reports_color = Color.CYAN
                info_parts.append(f"{reports_color}{reports}rep{Color.RESET}")
            
            # Skip usage type if it's the common "Data Center/Web Hosting/Transit"
            usage = result.get("usage_type", "")
            if usage and usage != "Data Center/Web Hosting/Transit":
                info_parts.append(usage.replace("Data Center/Web Hosting/Transit", "Hosting")[:15])
            
            print(f"   AB: {' | '.join(info_parts)}")
        
        elif service == "IPInfo":
            info_parts = []
            
            if result.get("city") and result.get("country"):
                location = f"{result['city']}, {result['country']}"
                info_parts.append(location)
            
            # Skip organization if it's redundant with VT owner
            if result.get("org"):
                org = result['org']
                # Don't show if it's similar to what VT already showed
                if not any(name in org.upper() for name in ["DIGITALOCEAN", "GOOGLE", "COLOCROSSING"]):
                    info_parts.append(org[:25])
            
            if info_parts:
                print(f"   IP: {' | '.join(info_parts)}")
    
    def _display_url_result(self, result: Dict[str, Any], original_defanged: Optional[str] = None) -> None:
        """
        Display URL analysis results in a clean format.
        
        Args:
            result: URL analysis result from VirusTotal
            original_defanged: Original defanged URL
        """
        if "error" in result:
            print(f"   {Color.RED}ERROR: {result['error']}{Color.RESET}")
            return
        
        reputation = result.get("reputation_score", "Unknown")
        stats = result.get("reputation_stats", {})
        malicious_count = stats.get('malicious', 0)
        total_count = sum(stats.values()) if stats else 0
        
        # Choose appropriate status indicator and color
        if reputation == "Malicious":
            if malicious_count >= 10:
                status_indicator = f"{Color.RED}[MALICIOUS]{Color.RESET}"
            elif malicious_count >= 5:
                status_indicator = f"{Color.YELLOW}[MALICIOUS]{Color.RESET}"
            else:
                status_indicator = f"{Color.YELLOW}[MALICIOUS]{Color.RESET}"
            self.stats["malicious_urls"] += 1
        elif reputation == "Suspicious":
            if malicious_count >= 3:
                status_indicator = f"{Color.YELLOW}[SUSPICIOUS]{Color.RESET}"
            else:
                status_indicator = f"{Color.CYAN}[SUSPICIOUS]{Color.RESET}"
        else:
            status_indicator = f"{Color.GREEN}[CLEAN]{Color.RESET}"
        
        print(f"   Status: {status_indicator} {reputation}")
        
        # Color the detection count
        if malicious_count == 0:
            detection_color = Color.GREEN
        elif malicious_count <= 3:
            detection_color = Color.YELLOW
        else:
            detection_color = Color.RED
        
        print(f"   Detections: {detection_color}{malicious_count}/{total_count}{Color.RESET} engines")
        
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
                print(f"   Threats: {Color.RED}{', '.join(threat_names)}{Color.RESET}")
    
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