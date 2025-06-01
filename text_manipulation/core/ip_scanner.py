"""
IP address scanner for bulk checking against threat intelligence APIs.

This module coordinates scanning of multiple IP addresses against
VirusTotal, AbuseIPDB, and IPInfo APIs with rate limiting and batch processing.
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
from pathlib import Path

from .api_clients.virustotal import VirusTotalClient
from .api_clients.abuseipdb import AbuseIPDBClient
from .api_clients.ipinfo import IPInfoClient
from .config import APIConfig


class IPScanner:
    """Manages bulk IP address scanning against threat intelligence and geolocation services."""
    
    def __init__(self):
        """Initialize IP scanner with API clients."""
        self.config = APIConfig()
        self._setup_api_clients()
        self.scan_results = []
        
    def _setup_api_clients(self) -> None:
        """Set up API clients if keys are available."""
        self.virustotal_client = None
        self.abuseipdb_client = None
        self.ipinfo_client = None
        
        if self.config.virustotal_api_key:
            self.virustotal_client = VirusTotalClient(self.config.virustotal_api_key)
            
        if self.config.abuseipdb_api_key:
            self.abuseipdb_client = AbuseIPDBClient(self.config.abuseipdb_api_key)
        
        # IPInfo works with or without API key (free tier available)
        self.ipinfo_client = IPInfoClient(self.config.ipinfo_api_key)
    
    async def scan_single_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Scan a single IP address against all available services.
        
        Args:
            ip_address: IP address to scan
            
        Returns:
            Combined scan results from all services
        """
        results = {
            "ip": ip_address,
            "scan_timestamp": datetime.now().isoformat(),
            "virustotal": None,
            "abuseipdb": None,
            "ipinfo": None
        }
        
        # Run scans in parallel
        tasks = []
        
        if self.virustotal_client:
            tasks.append(self.virustotal_client.check_ip_reputation(ip_address))
        
        if self.abuseipdb_client:
            tasks.append(self.abuseipdb_client.check_ip_abuse(ip_address))
        
        if self.ipinfo_client:
            tasks.append(self.ipinfo_client.get_ip_info(ip_address))
        
        if tasks:
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Assign results
            result_index = 0
            if self.virustotal_client:
                results["virustotal"] = scan_results[result_index]
                result_index += 1
            
            if self.abuseipdb_client:
                results["abuseipdb"] = scan_results[result_index]
                result_index += 1
            
            if self.ipinfo_client:
                results["ipinfo"] = scan_results[result_index]
        
        return results
    
    async def scan_ip_list(
        self, 
        ip_addresses: List[str], 
        batch_size: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Scan a list of IP addresses with rate limiting.
        
        Args:
            ip_addresses: List of IP addresses to scan
            batch_size: Number of IPs to scan concurrently
            
        Returns:
            List of scan results for all IP addresses
        """
        results = []
        
        # Process IPs in batches to avoid rate limiting
        for i in range(0, len(ip_addresses), batch_size):
            batch = ip_addresses[i:i + batch_size]
            batch_tasks = [self.scan_single_ip(ip) for ip in batch]
            batch_results = await asyncio.gather(*batch_tasks)
            results.extend(batch_results)
            
            # Add delay between batches to respect rate limits
            if i + batch_size < len(ip_addresses):
                await asyncio.sleep(1)  # 1 second delay between batches
        
        self.scan_results = results
        return results
    
    def export_results(self, filepath: Path) -> None:
        """
        Export scan results to JSON file.
        
        Args:
            filepath: Path to save results file
        """
        with open(filepath, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
    
    def get_summary_report(self) -> Dict[str, Any]:
        """
        Generate summary report of scan results.
        
        Returns:
            Summary statistics of the scan
        """
        total_ips = len(self.scan_results)
        malicious_ips = []
        suspicious_ips = []
        clean_ips = []
        
        for result in self.scan_results:
            ip = result["ip"]
            
            # Check VirusTotal results
            vt_result = result.get("virustotal", {})
            if vt_result and "reputation_score" in vt_result:
                if vt_result["reputation_score"] == "Malicious":
                    malicious_ips.append(ip)
                elif vt_result["reputation_score"] == "Suspicious":
                    suspicious_ips.append(ip)
            
            # Check AbuseIPDB results
            abuse_result = result.get("abuseipdb", {})
            if abuse_result and "abuse_confidence_score" in abuse_result:
                if abuse_result["abuse_confidence_score"] > 75:
                    if ip not in malicious_ips:
                        malicious_ips.append(ip)
                elif abuse_result["abuse_confidence_score"] > 25:
                    if ip not in suspicious_ips and ip not in malicious_ips:
                        suspicious_ips.append(ip)
        
        # IPs not in malicious or suspicious are considered clean
        for result in self.scan_results:
            ip = result["ip"]
            if ip not in malicious_ips and ip not in suspicious_ips:
                clean_ips.append(ip)
        
        return {
            "total_scanned": total_ips,
            "malicious_count": len(malicious_ips),
            "suspicious_count": len(suspicious_ips),
            "clean_count": len(clean_ips),
            "malicious_ips": malicious_ips,
            "suspicious_ips": suspicious_ips,
            "scan_timestamp": datetime.now().isoformat()
        } 