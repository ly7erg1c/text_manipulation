"""
CLI interface for clipboard polling mode.

This module provides the interactive interface for the clipboard monitoring
functionality, allowing users to configure and control the polling service.
"""

from typing import Optional
from ..core.polling_mode import ClipboardPoller
from ..core.config import APIConfig


class PollingInterface:
    """CLI interface for clipboard polling functionality."""
    
    def __init__(self):
        self.config = APIConfig()
        self.poller = None
        self._limit_poll = 1  # Default to scanning only first line
    
    def run(self) -> None:
        """Main interface for polling mode."""
        while True:
            self._display_polling_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self._start_monitoring()
            elif choice == '2':
                self._configure_polling_interval()
            elif choice == '3':
                self._configure_line_limit()
            elif choice == '4':
                self._check_api_status()
            elif choice == '5':
                self._show_help()
            else:
                print("Invalid option, please try again.")
    
    def _display_polling_menu(self) -> None:
        """Display the polling mode menu."""
        print("\n" + "=" * 70)
        print("           CLIPBOARD THREAT INTELLIGENCE MONITOR")
        print("=" * 70)
        print("\nSelect an option:")
        print("1. Start clipboard monitoring")
        print("2. Configure polling interval")
        print("3. Configure line scanning limit")
        print("4. Check API configuration status")
        print("5. Help & information")
        print("0. Back to main menu")
    
    def _start_monitoring(self) -> None:
        """Start the clipboard monitoring process."""
        # Check if we have at least one API configured
        has_apis = any([
            self.config.virustotal_api_key,
            self.config.abuseipdb_api_key,
            self.config.ipinfo_api_key
        ])
        
        if not has_apis:
            print("\nWARNING: No API keys configured!")
            print("   IP analysis will be limited to IPInfo free tier.")
            print("   Hash analysis requires VirusTotal API key.")
            print("\n   Go to 'API Configuration' in the main menu to set up API keys.")
            
            proceed = input("\n   Continue anyway? (y/N): ").strip().lower()
            if proceed != 'y':
                return
        
        # Get polling interval
        if hasattr(self, '_polling_interval'):
            interval = self._polling_interval
        else:
            interval = 2.0  # Default
        
        print(f"\nStarting clipboard monitor with {interval}s polling interval...")
        print(f"Line scanning limit: {'First line only' if self._limit_poll == 1 else f'First {self._limit_poll} lines'}")
        
        # Create and start poller
        self.poller = ClipboardPoller(poll_interval=interval, limit_poll=self._limit_poll)
        self.poller.start_polling()
    
    def _configure_polling_interval(self) -> None:
        """Configure the clipboard polling interval."""
        print("\n" + "=" * 50)
        print("         POLLING INTERVAL CONFIGURATION")
        print("=" * 50)
        print("\nCurrent polling interval: ", end="")
        
        if hasattr(self, '_polling_interval'):
            print(f"{self._polling_interval}s")
        else:
            print("2.0s (default)")
        
        print("\nRecommended intervals:")
        print("  - 1.0s - High responsiveness (higher CPU usage)")
        print("  - 2.0s - Balanced (recommended)")
        print("  - 5.0s - Conservative (lower CPU usage)")
        print("  - 10.0s - Minimal (very low CPU usage)")
        
        try:
            new_interval = input("\nEnter new polling interval in seconds (0.5-60): ").strip()
            
            if not new_interval:
                print("No changes made.")
                return
            
            interval = float(new_interval)
            
            if interval < 0.5 or interval > 60:
                print("ERROR: Invalid interval. Must be between 0.5 and 60 seconds.")
                return
            
            self._polling_interval = interval
            print(f"SUCCESS: Polling interval set to {interval}s")
            
        except ValueError:
            print("ERROR: Invalid input. Please enter a number.")
    
    def _configure_line_limit(self) -> None:
        """Configure the number of lines to scan from clipboard."""
        print("\n" + "=" * 50)
        print("         LINE SCANNING LIMIT CONFIGURATION")
        print("=" * 50)
        print(f"\nCurrent line limit: {'First line only' if self._limit_poll == 1 else f'First {self._limit_poll} lines'}")
        
        print("\nConfiguration options:")
        print("  - 1 - Scan only the first line (default, most efficient)")
        print("  - 2-10 - Scan first N lines (moderate performance)")
        print("  - 11+ - Scan more lines (higher resource usage)")
        print("\nNote: Only the first line is scanned unless limit is set > 1")
        
        try:
            new_limit = input("\nEnter number of lines to scan (1-50): ").strip()
            
            if not new_limit:
                print("No changes made.")
                return
            
            limit = int(new_limit)
            
            if limit < 1 or limit > 50:
                print("ERROR: Invalid limit. Must be between 1 and 50 lines.")
                return
            
            self._limit_poll = limit
            if limit == 1:
                print("SUCCESS: Line limit set to first line only")
            else:
                print(f"SUCCESS: Line limit set to first {limit} lines")
            
        except ValueError:
            print("ERROR: Invalid input. Please enter a number.")
    
    def _check_api_status(self) -> None:
        """Display current API configuration status."""
        print("\n" + "=" * 60)
        print("              API CONFIGURATION STATUS")
        print("=" * 60)
        
        # VirusTotal
        if self.config.virustotal_api_key:
            print("[CONFIGURED] VirusTotal API: Configured")
            print("   Enables: Hash analysis, IP reputation")
        else:
            print("[NOT CONFIGURED] VirusTotal API: Not configured")
            print("   Required for: Hash analysis")
        
        # AbuseIPDB
        if self.config.abuseipdb_api_key:
            print("[CONFIGURED] AbuseIPDB API: Configured")
            print("   Enables: IP abuse detection")
        else:
            print("[NOT CONFIGURED] AbuseIPDB API: Not configured")
            print("   Enhances: IP reputation analysis")
        
        # IPInfo
        if self.config.ipinfo_api_key:
            print("[CONFIGURED] IPInfo API: Configured (Enhanced)")
            print("   Enables: Enhanced geolocation data")
        else:
            print("[FREE TIER] IPInfo API: Using free tier")
            print("   Provides: Basic geolocation (limited)")
        
        print("\nTIP: Configure API keys in 'API Configuration' from main menu")
        
        # Show what will work with current config
        print("\nCurrent monitoring capabilities:")
        
        if self.config.virustotal_api_key:
            print("   [AVAILABLE] Hash analysis (MD5, SHA1, SHA256)")
        else:
            print("   [UNAVAILABLE] Hash analysis (requires VirusTotal)")
        
        print("   [AVAILABLE] IP address detection")
        
        if any([self.config.virustotal_api_key, self.config.abuseipdb_api_key]):
            print("   [AVAILABLE] IP threat intelligence")
        else:
            print("   [LIMITED] IP threat intelligence (limited)")
        
        print("   [AVAILABLE] Geolocation data")
    
    def _show_help(self) -> None:
        """Display help information about polling mode."""
        print("\n" + "=" * 70)
        print("                    POLLING MODE HELP")
        print("=" * 70)
        
        print("\nPURPOSE:")
        print("   The clipboard monitor automatically detects and analyzes")
        print("   security indicators (IOCs) when you copy them to clipboard.")
        
        print("\nDETECTS:")
        print("   - SHA256 hashes (64 characters)")
        print("   - SHA1 hashes (40 characters)")
        print("   - MD5 hashes (32 characters)")
        print("   - IPv4 addresses (xxx.xxx.xxx.xxx)")
        print("   - URLs")
        
        print("\nANALYSIS:")
        print("   - VirusTotal: File hash reputation & IP reputation")
        print("   - AbuseIPDB: IP abuse confidence scoring")
        print("   - IPInfo: Geolocation and organization data")
        
        print("\nCOLOR CODING:")
        print("   - GREEN: Clean/Safe (0 detections)")
        print("   - YELLOW: Low threat (1-3 detections) or Suspicious")
        print("   - RED: High threat (10+ detections) or confirmed Malicious")
        print("   - CYAN: Information/Neutral")
        
        print("\nHOW TO USE:")
        print("   1. Start monitoring from this menu")
        print("   2. Copy any text containing hashes or IPs")
        print("   3. Watch automatic analysis in the terminal")
        print("   4. Press Ctrl+C to stop monitoring")
        
        print("\nCONFIGURATION:")
        print("   - Polling interval: How often to check clipboard")
        print("   - Line limit: How many lines to scan (default: 1)")
        print("   - API keys: Configure in main menu for full features")
        
        print("\nTIPS:")
        print("   - Lower polling interval = faster detection, higher CPU")
        print("   - Line limit of 1 = most efficient, scans only first line")
        print("   - IOCs are only analyzed once (no duplicates)")
        print("   - Results stream in real-time as they're found")
        print("   - Session summary shows statistics when stopped")
        
        print("\nNOTES:")
        print("   - Requires API keys for full functionality")
        print("   - Clipboard access may be limited in some environments")
        print("   - Network connectivity required for threat intelligence")
        print("   - Default behavior: only first line is scanned unless limit > 1")
        
        input("\nPress Enter to continue...") 