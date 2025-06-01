#!/usr/bin/env python3
"""
Test script for the new cleaner IP analysis output formatting.
"""

import asyncio
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.abspath('.'))

from text_manipulation.core.polling_mode import ClipboardPoller
from text_manipulation.cli.display import Color


async def test_clean_output():
    """Test the new cleaner IP analysis output format."""
    
    # Create a poller instance
    poller = ClipboardPoller()
    
    print("Testing new cleaner IP analysis output format:")
    print("=" * 60)
    
    # Simulate the tree-style discovery message
    print("\n┌─ [17:21:09] New IOCs detected in clipboard")
    print("├─ Found 6 defanged IP(s)")
    print("└─ Processing 6 IP address(es)")
    print()
    
    # Test various IP scenarios with the new compact format
    
    # 1. High abuse IP
    print("🚨 167.71.81.114 - " + f"{Color.RED}ABUSE{Color.RESET}" + " (from 167.71.81[.]114)")
    print("   VT: " + f"{Color.RED}7/94{Color.RESET}" + " | US | DigitalOcean")
    print("   AB: " + f"{Color.RED}100%{Color.RESET}" + " | " + f"{Color.RED}778rep{Color.RESET}")
    print("   IP: Clifton, US")
    print("─" * 40)
    
    # 2. Possible abuse IP
    print("⚠️  34.172.240.9 - " + f"{Color.YELLOW}Possible Abuse{Color.RESET}" + " (from 34.172.240[.]9)")
    print("   VT: " + f"{Color.YELLOW}1/94{Color.RESET}" + " | US | Google Cloud")
    print("   AB: " + f"{Color.YELLOW}26%{Color.RESET}" + " | " + f"{Color.YELLOW}16rep{Color.RESET}")
    print("   IP: Council Bluffs, US")
    print("─" * 40)
    
    # 3. Clean IP
    print("✅ 34.19.127.223 - " + f"{Color.GREEN}CLEAN{Color.RESET}" + " (from 34.19.127[.]223)")
    print("   VT: " + f"{Color.GREEN}0/94{Color.RESET}" + " | US | Google Cloud")
    print("   AB: " + f"{Color.GREEN}12%{Color.RESET}" + " | " + f"{Color.CYAN}3rep{Color.RESET}")
    print("   IP: The Dalles, US")
    print("─" * 40)
    
    # 4. Another abuse case
    print("🚨 159.223.132.86 - " + f"{Color.RED}ABUSE{Color.RESET}" + " (from 159.223.132[.]86)")
    print("   VT: " + f"{Color.RED}8/94{Color.RESET}" + " | US | DigitalOcean")
    print("   AB: " + f"{Color.RED}100%{Color.RESET}" + " | " + f"{Color.RED}829rep{Color.RESET}")
    print("   IP: North Bergen, US")
    print("─" * 40)


if __name__ == "__main__":
    asyncio.run(test_clean_output()) 