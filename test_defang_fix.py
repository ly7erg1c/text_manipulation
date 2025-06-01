#!/usr/bin/env python3
"""
Test script to verify defang functionality fixes.
"""

from text_manipulation.core.extractors import NetworkExtractor, DefangUtility

def test_ip_detection():
    """Test IP detection and defanging."""
    print("Testing IP detection and defanging:")
    test_ips = [
        '192.168.1.1',
        '10.0.0.1',
        '172.16.254.1',
        '8.8.8.8'
    ]
    
    for ip in test_ips:
        detected = NetworkExtractor.extract_ipv4(ip)
        is_ip = bool(detected)
        defanged = ip.replace('.', '[.]') if is_ip else "NOT DETECTED AS IP"
        print(f"  {ip} -> Detected: {is_ip} -> Defanged: {defanged}")

def test_url_defanging():
    """Test URL defanging with protocols."""
    print("\nTesting URL defanging:")
    test_text = "Visit http://192.168.1.1 and https://example.com for more info"
    
    print(f"Original: {test_text}")
    
    # Test using defang_urls method
    defanged_urls = NetworkExtractor.defang_urls(test_text)
    print(f"Defanged URLs: {defanged_urls}")
    
    # Test using defang_text utility
    defanged_text = DefangUtility.defang_text(test_text)
    print(f"Defanged text: {defanged_text}")

def test_manual_defang_logic():
    """Test the manual defang logic."""
    print("\nTesting manual defang logic:")
    test_cases = [
        '192.168.1.1',           # Should be detected as IP
        'http://192.168.1.1',    # Should be detected as IP (URL with IP)
        'https://example.com',   # Should be treated as URL
        'example.com',           # Should be treated as URL/domain
        'no-dots-here'           # Should be rejected
    ]
    
    for test_input in test_cases:
        print(f"\n  Testing: {test_input}")
        
        # Simulate the manual defang logic
        if NetworkExtractor.extract_ipv4(test_input):
            # It's an IP address
            defanged = test_input.replace('.', '[.]')
            print(f"    Detected as IP -> {defanged}")
        elif '.' in test_input:  # Assume it's a URL or domain
            # First replace protocols, then dots
            defanged = test_input.replace('http://', 'hxxp://')
            defanged = defanged.replace('https://', 'hxxps://')
            defanged = defanged.replace('.', '[.]')
            print(f"    Treated as URL/domain -> {defanged}")
        else:
            print(f"    Rejected (no dots)")

if __name__ == "__main__":
    test_ip_detection()
    test_url_defanging()
    test_manual_defang_logic()