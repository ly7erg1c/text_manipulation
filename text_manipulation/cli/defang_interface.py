"""
Defang/Unfang interface for URL and IP address manipulation.

This module provides an interactive interface for defanging and unfanging
URLs and IP addresses for cybersecurity purposes.
"""

from typing import Set, Optional
import pyperclip

from ..core.extractors import NetworkExtractor, DefangUtility
from .input_handler import InputHandler
from .display import DisplayManager


class DefangInterface:
    """Interface for defanging and unfanging operations."""
    
    def __init__(self):
        """Initialize the defang interface."""
        self.network_extractor = NetworkExtractor()
        self.defang_utility = DefangUtility()
        self.input_handler = InputHandler()
        self.display = DisplayManager()
        self.text = ""
    
    def run(self) -> None:
        """Run the defang interface."""
        print("\n" + "=" * 80)
        print("               DEFANG/UNFANG UTILITY")
        print("=" * 80)
        print("\nThis tool helps you defang and unfang URLs and IP addresses")
        print("for safe sharing in cybersecurity contexts.")
        
        # Check if we have text to work with
        if not self.text:
            self._prompt_for_input()
        
        while True:
            self._display_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self._extract_and_defang_all()
            elif choice == '2':
                self._extract_and_defang_ips()
            elif choice == '3':
                self._extract_and_defang_urls()
            elif choice == '4':
                self._defang_entire_text()
            elif choice == '5':
                self._unfang_entire_text()
            elif choice == '6':
                self._manual_defang()
            elif choice == '7':
                self._manual_unfang()
            elif choice == '8':
                self._input_new_text()
            elif choice == '9':
                self._show_current_text()
            else:
                print("Invalid option, please try again.")
    
    def _display_menu(self) -> None:
        """Display the defang menu options."""
        print("\n" + "=" * 60)
        print("           DEFANG/UNFANG OPTIONS")
        print("=" * 60)
        print("\nAutomatic Extraction & Defanging:")
        print("1. Extract and defang all URLs and IPs")
        print("2. Extract and defang IP addresses only")
        print("3. Extract and defang URLs only")
        print("\nBulk Text Processing:")
        print("4. Defang entire text (all URLs and IPs)")
        print("5. Unfang entire text (restore all defanged items)")
        print("\nManual Operations:")
        print("6. Manually defang specific URL/IP")
        print("7. Manually unfang specific URL/IP")
        print("\nData Management:")
        print("8. Input new text")
        print("9. Show current text")
        print("0. Back to main menu")
    
    def _prompt_for_input(self) -> None:
        """Prompt user for initial text input."""
        print("\nTo use the defang utility, please provide some text containing URLs or IP addresses.")
        response = input("Would you like to input text now? (y/n): ").strip().lower()
        
        if response in ['y', 'yes']:
            self.text = self.input_handler.get_text_input()
            if self.text:
                print(f"\n✓ Text loaded successfully! ({len(self.text)} characters)")
            else:
                print("No text was provided. You can input text later using option 8.")
        else:
            print("You can input text later using option 8.")
    
    def _extract_and_defang_all(self) -> None:
        """Extract and defang all URLs and IP addresses."""
        if not self._ensure_text_available():
            return
        
        # Extract all IOCs
        all_iocs = self.network_extractor.extract_all_ips_and_urls(self.text)
        
        # Defang the extracted IOCs
        defanged_ips = {self.network_extractor.unfang_ipv4(ip).replace('.', '[.]') 
                       for ip in all_iocs['ipv4']}
        defanged_urls = self.network_extractor.defang_urls(self.text)
        
        self.display.clear_screen()
        print("\n" + "=" * 80)
        print("           EXTRACTED AND DEFANGED IOCs")
        print("=" * 80)
        
        total_found = len(defanged_ips) + len(defanged_urls) + len(all_iocs['defanged_ipv4']) + len(all_iocs['defanged_urls'])
        
        if total_found == 0:
            print("\nNo URLs or IP addresses found in the text.")
            input("\nPress Enter to continue...")
            return
        
        # Display results
        if defanged_ips or all_iocs['defanged_ipv4']:
            print(f"\n📍 DEFANGED IP ADDRESSES ({len(defanged_ips) + len(all_iocs['defanged_ipv4'])}):")
            for ip in defanged_ips:
                print(f"   {ip}")
            for ip in all_iocs['defanged_ipv4']:
                print(f"   {ip} (already defanged)")
        
        if defanged_urls or all_iocs['defanged_urls']:
            print(f"\n🔗 DEFANGED URLs ({len(defanged_urls) + len(all_iocs['defanged_urls'])}):")
            for url in defanged_urls:
                print(f"   {url}")
            for url in all_iocs['defanged_urls']:
                print(f"   {url} (already defanged)")
        
        # Prepare output for clipboard
        all_defanged = list(defanged_ips) + list(defanged_urls) + list(all_iocs['defanged_ipv4']) + list(all_iocs['defanged_urls'])
        output = '\n'.join(all_defanged)
        self._copy_to_clipboard(output)
        
        input("\nPress Enter to continue...")
    
    def _extract_and_defang_ips(self) -> None:
        """Extract and defang IP addresses only."""
        if not self._ensure_text_available():
            return
        
        ips = self.network_extractor.extract_ipv4(self.text)
        defanged_ips_existing = self.network_extractor.extract_defanged_ipv4(self.text)
        defanged_ips = {ip.replace('.', '[.]') for ip in ips}
        
        self.display.clear_screen()
        print("\n" + "=" * 60)
        print("           DEFANGED IP ADDRESSES")
        print("=" * 60)
        
        total_found = len(defanged_ips) + len(defanged_ips_existing)
        
        if total_found == 0:
            print("\nNo IP addresses found in the text.")
        else:
            print(f"\nFound {total_found} IP address(es):")
            
            for ip in defanged_ips:
                print(f"   {ip}")
            
            for ip in defanged_ips_existing:
                print(f"   {ip} (already defanged)")
            
            # Copy to clipboard
            all_ips = list(defanged_ips) + list(defanged_ips_existing)
            output = '\n'.join(all_ips)
            self._copy_to_clipboard(output)
        
        input("\nPress Enter to continue...")
    
    def _extract_and_defang_urls(self) -> None:
        """Extract and defang URLs only."""
        if not self._ensure_text_available():
            return
        
        defanged_urls = self.network_extractor.defang_urls(self.text)
        existing_defanged = self.network_extractor.extract_defanged_urls(self.text)
        
        self.display.clear_screen()
        print("\n" + "=" * 60)
        print("           DEFANGED URLs")
        print("=" * 60)
        
        total_found = len(defanged_urls) + len(existing_defanged)
        
        if total_found == 0:
            print("\nNo URLs found in the text.")
        else:
            print(f"\nFound {total_found} URL(s):")
            
            for url in defanged_urls:
                print(f"   {url}")
            
            for url in existing_defanged:
                print(f"   {url} (already defanged)")
            
            # Copy to clipboard
            all_urls = list(defanged_urls) + list(existing_defanged)
            output = '\n'.join(all_urls)
            self._copy_to_clipboard(output)
        
        input("\nPress Enter to continue...")
    
    def _defang_entire_text(self) -> None:
        """Defang all URLs and IPs in the entire text."""
        if not self._ensure_text_available():
            return
        
        defanged_text = self.defang_utility.defang_text(self.text)
        
        self.display.clear_screen()
        print("\n" + "=" * 60)
        print("           DEFANGED TEXT")
        print("=" * 60)
        print("\nDefanged text (all URLs and IPs have been defanged):")
        print("-" * 60)
        print(defanged_text)
        
        self._copy_to_clipboard(defanged_text)
        input("\nPress Enter to continue...")
    
    def _unfang_entire_text(self) -> None:
        """Unfang all defanged URLs and IPs in the entire text."""
        if not self._ensure_text_available():
            return
        
        unfanged_text = self.defang_utility.unfang_text(self.text)
        
        self.display.clear_screen()
        print("\n" + "=" * 60)
        print("           UNFANGED TEXT")
        print("=" * 60)
        print("\nUnfanged text (all defanged URLs and IPs have been restored):")
        print("-" * 60)
        print(unfanged_text)
        
        self._copy_to_clipboard(unfanged_text)
        input("\nPress Enter to continue...")
    
    def _manual_defang(self) -> None:
        """Manually defang a specific URL or IP address."""
        print("\n" + "=" * 60)
        print("           MANUAL DEFANG")
        print("=" * 60)
        
        user_input = input("\nEnter a URL or IP address to defang: ").strip()
        
        if not user_input:
            print("No input provided.")
            input("\nPress Enter to continue...")
            return
        
        # Try to determine if it's an IP or URL and defang accordingly
        if self.network_extractor.extract_ipv4(user_input):
            # It's an IP address
            defanged = user_input.replace('.', '[.]')
            print(f"\nOriginal:  {user_input}")
            print(f"Defanged:  {defanged}")
        elif '.' in user_input:  # Assume it's a URL or domain
            # First replace protocols, then dots
            defanged = user_input.replace('http://', 'hxxp://')
            defanged = defanged.replace('https://', 'hxxps://')
            defanged = defanged.replace('.', '[.]')
            print(f"\nOriginal:  {user_input}")
            print(f"Defanged:  {defanged}")
        else:
            print(f"\nInput doesn't appear to be a URL or IP address: {user_input}")
            input("\nPress Enter to continue...")
            return
        
        self._copy_to_clipboard(defanged)
        input("\nPress Enter to continue...")
    
    def _manual_unfang(self) -> None:
        """Manually unfang a specific defanged URL or IP address."""
        print("\n" + "=" * 60)
        print("           MANUAL UNFANG")
        print("=" * 60)
        
        user_input = input("\nEnter a defanged URL or IP address to unfang: ").strip()
        
        if not user_input:
            print("No input provided.")
            input("\nPress Enter to continue...")
            return
        
        # Unfang the input
        unfanged = self.defang_utility.unfang_text(user_input)
        
        if unfanged != user_input:
            print(f"\nDefanged:  {user_input}")
            print(f"Unfanged:  {unfanged}")
            self._copy_to_clipboard(unfanged)
        else:
            print(f"\nInput doesn't appear to be defanged: {user_input}")
        
        input("\nPress Enter to continue...")
    
    def _input_new_text(self) -> None:
        """Input new text for processing."""
        print("\n" + "=" * 60)
        print("           INPUT NEW TEXT")
        print("=" * 60)
        
        self.text = self.input_handler.get_text_input()
        if self.text:
            print(f"\n✓ Text loaded successfully! ({len(self.text)} characters)")
        else:
            print("No text was provided.")
        
        input("\nPress Enter to continue...")
    
    def _show_current_text(self) -> None:
        """Show information about the current text."""
        if not self.text:
            print("\nNo text currently loaded.")
        else:
            lines = self.text.split('\n')
            words = self.text.split()
            
            # Get IOC counts
            all_iocs = self.network_extractor.extract_all_ips_and_urls(self.text)
            total_ips = len(all_iocs['ipv4']) + len(all_iocs['defanged_ipv4'])
            total_urls = len(all_iocs['urls']) + len(all_iocs['defanged_urls'])
            
            print(f"\n📄 Current Text Information:")
            print(f"   Characters: {len(self.text)}")
            print(f"   Lines: {len(lines)}")
            print(f"   Words: {len(words)}")
            print(f"   IP addresses: {total_ips} ({len(all_iocs['defanged_ipv4'])} already defanged)")
            print(f"   URLs: {total_urls} ({len(all_iocs['defanged_urls'])} already defanged)")
            
            # Show first few lines as preview
            if lines:
                print(f"\n📋 Preview (first 3 lines):")
                for i, line in enumerate(lines[:3]):
                    preview = line[:80] + "..." if len(line) > 80 else line
                    print(f"   {i+1}: {preview}")
        
        input("\nPress Enter to continue...")
    
    def _ensure_text_available(self) -> bool:
        """
        Ensure text is available for operations.
        
        Returns:
            True if text is available, False otherwise
        """
        if not self.text:
            print("\nNo text input provided. Please input text first.")
            response = input("Would you like to input text now? (y/n): ").strip().lower()
            
            if response in ['y', 'yes']:
                self.text = self.input_handler.get_text_input()
                if self.text:
                    print(f"\n✓ Text loaded successfully! ({len(self.text)} characters)")
                    return True
                else:
                    print("No text was provided.")
                    return False
            else:
                return False
        return True
    
    def _copy_to_clipboard(self, output: str) -> None:
        """
        Copy output to clipboard.
        
        Args:
            output: Text to copy to clipboard
        """
        if output:
            try:
                pyperclip.copy(output)
                print(f"\n✓ Copied to clipboard ({len(output)} characters)")
            except Exception as e:
                print(f"\n⚠ Failed to copy to clipboard: {e}")
        else:
            print("\n⚠ Nothing to copy to clipboard") 