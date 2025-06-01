#!/usr/bin/env python3
"""
Simple test script to verify color output functionality in polling mode.
"""

from text_manipulation.cli.display import Color
from text_manipulation.core.polling_mode import ClipboardPoller


def test_color_output():
    """Test the color output functionality."""
    print(f"{Color.CYAN}=== COLOR OUTPUT TEST ==={Color.RESET}")
    
    # Test basic colors
    print(f"\n{Color.GREEN}✓ GREEN - Clean/Safe{Color.RESET}")
    print(f"{Color.YELLOW}⚠ YELLOW - Low/Medium Threat{Color.RESET}")
    print(f"{Color.RED}✗ RED - High Threat{Color.RESET}")
    print(f"{Color.CYAN}ℹ CYAN - Information{Color.RESET}")
    
    # Test status indicators like they would appear in polling
    print(f"\n{Color.BOLD}Hash Analysis Examples:{Color.RESET}")
    print(f"   Status: {Color.GREEN}[CLEAN]{Color.RESET} Clean")
    print(f"   Detections: {Color.GREEN}0/73{Color.RESET} engines")
    
    print(f"   Status: {Color.YELLOW}[SUSPICIOUS]{Color.RESET} Suspicious")
    print(f"   Detections: {Color.YELLOW}2/73{Color.RESET} engines")
    
    print(f"   Status: {Color.RED}[MALICIOUS]{Color.RESET} Malicious")
    print(f"   Detections: {Color.RED}15/73{Color.RESET} engines")
    
    # Test IP analysis examples
    print(f"\n{Color.BOLD}IP Analysis Examples:{Color.RESET}")
    print(f"   VirusTotal:")
    print(f"      Status: {Color.GREEN}[CLEAN]{Color.RESET} Clean")
    print(f"      Detections: {Color.GREEN}0/89{Color.RESET} engines")
    
    print(f"   AbuseIPDB:")
    print(f"      Abuse Confidence: {Color.GREEN}[LOW] 5%{Color.RESET}")
    print(f"      Total Reports: {Color.CYAN}0{Color.RESET}")
    
    print(f"   AbuseIPDB (High Risk):")
    print(f"      Abuse Confidence: {Color.RED}[HIGH] 85%{Color.RESET}")
    print(f"      Total Reports: {Color.RED}150{Color.RESET}")


def test_polling_config():
    """Test the polling configuration with new parameters."""
    print(f"\n{Color.CYAN}=== POLLING CONFIGURATION TEST ==={Color.RESET}")
    
    # Test with different limit_poll values
    configs = [
        (2.0, 1),
        (1.5, 3),
        (3.0, 5)
    ]
    
    for interval, limit in configs:
        try:
            poller = ClipboardPoller(poll_interval=interval, limit_poll=limit)
            print(f"{Color.GREEN}✓{Color.RESET} Successfully created poller with interval={interval}s, limit_poll={limit}")
            print(f"   Poll interval: {poller.poll_interval}s")
            print(f"   Line limit: {poller.limit_poll}")
        except Exception as e:
            print(f"{Color.RED}✗{Color.RESET} Failed to create poller: {e}")


def main():
    """Main test function."""
    print(f"{Color.BOLD}{Color.CYAN}Enhanced Polling Mode - Color & Configuration Test{Color.RESET}")
    
    test_color_output()
    test_polling_config()
    
    print(f"\n{Color.GREEN}All tests completed successfully!{Color.RESET}")
    print(f"\n{Color.YELLOW}To test the actual polling functionality:{Color.RESET}")
    print(f"1. Run {Color.CYAN}python main.py{Color.RESET}")
    print(f"2. Select option {Color.CYAN}7{Color.RESET} (Polling Mode)")
    print(f"3. Configure line limit with option {Color.CYAN}3{Color.RESET}")
    print(f"4. Start monitoring with option {Color.CYAN}1{Color.RESET}")


if __name__ == "__main__":
    main() 