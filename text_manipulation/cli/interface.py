"""
Command-line interface for the text manipulation tool.

This module provides the interactive CLI for the text manipulation tool,
including menu systems and user input handling.
"""

import os
from typing import Optional, Set, Union
import pyperclip

from ..core.extractors import (
    HashExtractor, NetworkExtractor, FileExtractor, TextManipulator,
    CryptocurrencyExtractor, SecurityExtractor, EmailExtractor
)
from .input_handler import InputHandler
from .display import DisplayManager
from .ip_scanner_interface import IPScannerInterface
from .url_scanner_interface import URLScannerInterface
from .polling_interface import PollingInterface
from .defang_interface import DefangInterface
from ..core.config import APIConfig


class TextManipulationCLI:
    """Main CLI interface for the text manipulation tool."""
    
    def __init__(self):
        """Initialize CLI with all required components."""
        self.hash_extractor = HashExtractor()
        self.network_extractor = NetworkExtractor()
        self.file_extractor = FileExtractor()
        self.text_manipulator = TextManipulator()
        self.crypto_extractor = CryptocurrencyExtractor()
        self.security_extractor = SecurityExtractor()
        self.email_extractor = EmailExtractor()
        self.input_handler = InputHandler()
        self.display = DisplayManager()
        self.ip_scanner = IPScannerInterface()
        self.url_scanner = URLScannerInterface()
        self.polling_interface = PollingInterface()
        self.defang_interface = DefangInterface()
        self.config = APIConfig()
        self.text = ""
        self.previous_output = ""
    
    def display_main_menu(self) -> None:
        """Display main menu with categories."""
        print("\n" + "=" * 60)
        print("           TEXT MANIPULATION TOOL")
        print("=" * 60)
        print("\nSelect a category:")
        print("1. Hash Extraction")
        print("2. Network Analysis")
        print("3. Cryptocurrency Extraction")
        print("4. Security Artifacts")
        print("5. Email Extraction")
        print("6. File Operations") 
        print("7. Text Manipulation")
        print("8. Data Input/Management")
        print("9. API Configuration")
        print("10. Polling Mode")
        print("11. Defang/Unfang Utility")
        print("0. Exit")

    def display_hash_menu(self) -> None:
        """Display hash extraction submenu."""
        print("\n" + "=" * 60)
        print("           HASH EXTRACTION")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Extract SHA256 hashes")
        print("2. Extract SHA1 hashes")
        print("3. Extract MD5 hashes")
        print("4. Extract SSL certificate fingerprints")
        print("0. Back to main menu")

    def display_network_menu(self) -> None:
        """Display network analysis submenu."""
        print("\n" + "=" * 60)
        print("           NETWORK ANALYSIS")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Extract IPv4 addresses")
        print("2. Extract IPv6 addresses")
        print("3. Extract URLs")
        print("4. Extract domains")
        print("5. Extract CIDR networks")
        print("6. Extract ports")
        print("7. Extract MAC addresses")
        print("8. Extract ASN numbers")
        print("9. Extract all network data")
        print("10. IP Address Threat Intelligence Scanner")
        print("11. URL Threat Intelligence Scanner")
        print("0. Back to main menu")

    def display_crypto_menu(self) -> None:
        """Display cryptocurrency extraction submenu."""
        print("\n" + "=" * 60)
        print("           CRYPTOCURRENCY EXTRACTION")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Extract Bitcoin addresses")
        print("2. Extract Ethereum addresses")
        print("3. Extract Litecoin addresses")
        print("4. Extract Monero addresses")
        print("5. Extract all cryptocurrency addresses")
        print("0. Back to main menu")

    def display_security_menu(self) -> None:
        """Display security artifacts submenu."""
        print("\n" + "=" * 60)
        print("           SECURITY ARTIFACTS")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Extract CVE identifiers")
        print("2. Extract YARA rules")
        print("3. Extract Windows registry keys")
        print("0. Back to main menu")

    def display_email_menu(self) -> None:
        """Display email extraction submenu."""
        print("\n" + "=" * 60)
        print("           EMAIL EXTRACTION")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Extract email addresses")
        print("0. Back to main menu")

    def display_file_menu(self) -> None:
        """Display file operations submenu."""
        print("\n" + "=" * 60)
        print("           FILE OPERATIONS")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Extract executable files")
        print("0. Back to main menu")

    def display_text_menu(self) -> None:
        """Display text manipulation submenu."""
        print("\n" + "=" * 60)
        print("           TEXT MANIPULATION")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Convert newlines to spaces")
        print("2. Remove blank lines")
        print("0. Back to main menu")

    def display_data_menu(self) -> None:
        """Display data input/management submenu."""
        print("\n" + "=" * 60)
        print("           DATA INPUT/MANAGEMENT")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Input new text")
        print("2. View current text info")
        print("3. Clear current text")
        print("0. Back to main menu")

    def display_api_menu(self) -> None:
        """Display API configuration submenu."""
        print("\n" + "=" * 60)
        print("           API CONFIGURATION")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Set IPInfo API Key")
        print("2. Set VirusTotal API Key")
        print("3. Set AbuseIPDB API Key")
        print("4. View current API configuration")
        print("5. Clear all API keys")
        print("0. Back to main menu")
    
    def run(self) -> None:
        """Main CLI loop."""
        self.display.show_welcome()
        
        # Initial prompt for data input
        self._prompt_initial_data_input()
        
        while True:
            self.display_main_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                print("\nGoodbye!")
                break
            elif choice == '1':
                self._handle_hash_menu()
            elif choice == '2':
                self._handle_network_menu()
            elif choice == '3':
                self._handle_crypto_menu()
            elif choice == '4':
                self._handle_security_menu()
            elif choice == '5':
                self._handle_email_menu()
            elif choice == '6':
                self._handle_file_menu()
            elif choice == '7':
                self._handle_text_menu()
            elif choice == '8':
                self._handle_data_menu()
            elif choice == '9':
                self._handle_api_menu()
            elif choice == '10':
                self._handle_polling_menu()
            elif choice == '11':
                self._handle_defang_menu()
            else:
                print("Invalid option, please try again.")

    def _handle_hash_menu(self) -> None:
        """Handle hash extraction submenu."""
        while True:
            self.display_hash_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice in ['1', '2', '3', '4']:
                if not self._ensure_text_available():
                    continue
                    
                if choice == '1':
                    result = self.hash_extractor.extract_sha256(self.text)
                    self._display_and_store_output(result)
                elif choice == '2':
                    result = self.hash_extractor.extract_sha1(self.text)
                    self._display_and_store_output(result)
                elif choice == '3':
                    result = self.hash_extractor.extract_md5(self.text)
                    self._display_and_store_output(result)
                elif choice == '4':
                    result = self.hash_extractor.extract_ssl_certificate_fingerprints(self.text)
                    self._display_and_store_output(result)
                
                input("\nPress Enter to continue...")
            else:
                print("Invalid option, please try again.")

    def _handle_network_menu(self) -> None:
        """Handle network analysis submenu."""
        while True:
            self.display_network_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice == '10':
                self.display.clear_screen()
                self.ip_scanner.run()
                input("\nPress Enter to continue...")
            elif choice == '11':
                self.display.clear_screen()
                self.url_scanner.run()
                input("\nPress Enter to continue...")
            elif choice in ['1', '2', '3', '4', '5', '6', '7', '8', '9']:
                if not self._ensure_text_available():
                    continue
                    
                if choice == '1':
                    result = self.network_extractor.extract_ipv4(self.text)
                    self._display_and_store_output(result)
                elif choice == '2':
                    result = self.network_extractor.extract_ipv6(self.text)
                    self._display_and_store_output(result)
                elif choice == '3':
                    result = self.network_extractor.extract_urls(self.text)
                    self._display_and_store_output(result)
                elif choice == '4':
                    result = self.network_extractor.extract_domains(self.text)
                    self._display_and_store_output(result)
                elif choice == '5':
                    result = self.network_extractor.extract_cidr_networks(self.text)
                    self._display_and_store_output(result)
                elif choice == '6':
                    result = self.network_extractor.extract_ports(self.text)
                    self._display_and_store_output(result)
                elif choice == '7':
                    result = self.network_extractor.extract_mac_addresses(self.text)
                    self._display_and_store_output(result)
                elif choice == '8':
                    result = NetworkExtractor.extract_asn(self.text)
                    self._display_and_store_output(result)
                elif choice == '9':
                    result = NetworkExtractor.extract_all_network_data(self.text)
                    self._display_and_store_output(result)
                
                input("\nPress Enter to continue...")
            else:
                print("Invalid option, please try again.")

    def _handle_crypto_menu(self) -> None:
        """Handle cryptocurrency extraction submenu."""
        while True:
            self.display_crypto_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice in ['1', '2', '3', '4', '5']:
                if not self._ensure_text_available():
                    continue
                    
                if choice == '1':
                    result = CryptocurrencyExtractor.extract_bitcoin(self.text)
                    self._display_and_store_output(result)
                elif choice == '2':
                    result = CryptocurrencyExtractor.extract_ethereum(self.text)
                    self._display_and_store_output(result)
                elif choice == '3':
                    result = CryptocurrencyExtractor.extract_litecoin(self.text)
                    self._display_and_store_output(result)
                elif choice == '4':
                    result = CryptocurrencyExtractor.extract_monero(self.text)
                    self._display_and_store_output(result)
                elif choice == '5':
                    result = CryptocurrencyExtractor.extract_all_crypto(self.text)
                    self._display_and_store_output(result)
                
                input("\nPress Enter to continue...")
            else:
                print("Invalid option, please try again.")

    def _handle_security_menu(self) -> None:
        """Handle security artifacts submenu."""
        while True:
            self.display_security_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice in ['1', '2', '3']:
                if not self._ensure_text_available():
                    continue
                    
                if choice == '1':
                    result = SecurityExtractor.extract_cve(self.text)
                    self._display_and_store_output(result)
                elif choice == '2':
                    result = SecurityExtractor.extract_yara_rules(self.text)
                    self._display_and_store_output(result)
                elif choice == '3':
                    result = SecurityExtractor.extract_registry_keys(self.text)
                    self._display_and_store_output(result)
                
                input("\nPress Enter to continue...")
            else:
                print("Invalid option, please try again.")

    def _handle_email_menu(self) -> None:
        """Handle email extraction submenu."""
        while True:
            self.display_email_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                if not self._ensure_text_available():
                    continue
                    
                result = EmailExtractor.extract_emails(self.text)
                self._display_and_store_output(result)
                input("\nPress Enter to continue...")
            else:
                print("Invalid option, please try again.")

    def _handle_file_menu(self) -> None:
        """Handle file operations submenu."""
        while True:
            self.display_file_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                if not self._ensure_text_available():
                    continue
                    
                result = self.file_extractor.extract_executables(self.text)
                self._display_and_store_output(result)
                input("\nPress Enter to continue...")
            else:
                print("Invalid option, please try again.")

    def _handle_text_menu(self) -> None:
        """Handle text manipulation submenu."""
        while True:
            self.display_text_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice in ['1', '2']:
                if not self._ensure_text_available():
                    continue
                    
                if choice == '1':
                    result = self.text_manipulator.newline_to_space(self.text)
                    self._display_and_store_output(result)
                elif choice == '2':
                    result = self.text_manipulator.remove_blank_lines(self.text)
                    self._display_and_store_output(result)
                
                input("\nPress Enter to continue...")
            else:
                print("Invalid option, please try again.")

    def _handle_data_menu(self) -> None:
        """Handle data input/management submenu."""
        while True:
            self.display_data_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self.text = self.input_handler.get_input()
                if self.text:
                    print(f"\nText loaded successfully! ({len(self.text)} characters)")
            elif choice == '2':
                self._show_text_info()
                input("\nPress Enter to continue...")
            elif choice == '3':
                self._clear_text()
            else:
                print("Invalid option, please try again.")

    def _handle_api_menu(self) -> None:
        """Handle API configuration submenu."""
        while True:
            self.display_api_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self._set_api_key('IPINFO_API_KEY', 'IPInfo')
            elif choice == '2':
                self._set_api_key('VIRUSTOTAL_API_KEY', 'VirusTotal')
            elif choice == '3':
                self._set_api_key('ABUSEIPDB_API_KEY', 'AbuseIPDB')
            elif choice == '4':
                self._show_api_configuration()
                input("\nPress Enter to continue...")
            elif choice == '5':
                self._clear_api_keys()
            else:
                print("Invalid option, please try again.")

    def _handle_polling_menu(self) -> None:
        """Handle clipboard polling submenu."""
        self.display.clear_screen()
        self.polling_interface.run()
        input("\nPress Enter to continue...")

    def _handle_defang_menu(self) -> None:
        """Handle defang/unfang utility submenu."""
        self.display.clear_screen()
        self.defang_interface.run()
        input("\nPress Enter to continue...")

    def _ensure_text_available(self) -> bool:
        """
        Ensure text is available for operations. Prompt user if not.
        
        Returns:
            True if text is available, False if user cancels
        """
        if not self.text:
            print("\nNo text input provided. Please input text first.")
            response = input("Would you like to input text now? (y/n): ").strip().lower()
            
            if response in ['y', 'yes']:
                self.text = self.input_handler.get_text_input()
                if self.text:
                    print(f"\n✓ Data loaded successfully! ({len(self.text)} characters)")
                    return True
                else:
                    print("No text was provided.")
                    return False
            else:
                return False
        return True

    def _show_text_info(self) -> None:
        """Display information about the current text."""
        if not self.text:
            print("\nNo text currently loaded.")
        else:
            lines = self.text.split('\n')
            words = self.text.split()
            print(f"\n📄 Current Text Information:")
            print(f"   Characters: {len(self.text)}")
            print(f"   Lines: {len(lines)}")
            print(f"   Words: {len(words)}")
            print(f"   Non-empty lines: {len([line for line in lines if line.strip()])}")
            
            # Show first few lines as preview
            if lines:
                print(f"\n📋 Preview (first 3 lines):")
                for i, line in enumerate(lines[:3]):
                    preview = line[:80] + "..." if len(line) > 80 else line
                    print(f"   {i+1}: {preview}")

    def _clear_text(self) -> None:
        """Clear the current text."""
        if not self.text:
            print("\nNo text to clear.")
        else:
            confirm = input("\nAre you sure you want to clear the current text? (y/n): ").strip().lower()
            if confirm in ['y', 'yes']:
                self.text = ""
                self.previous_output = ""
                print("\n✓ Text cleared successfully.")
            else:
                print("\nText not cleared.")
    
    def _display_and_store_output(self, output: Union[Set[str], str]) -> None:
        """Display output and store it for clipboard operations."""
        self.display.clear_screen()
        self.display.show_output_header()
        
        if isinstance(output, set):
            if output:
                for item in output:
                    print(item)
                self.previous_output = '\n'.join(output)
            else:
                print("No results found.")
                self.previous_output = ""
        else:
            print(output)
            self.previous_output = output
        
        # Automatically copy to clipboard
        self._copy_to_clipboard(self.previous_output)
    
    def _copy_to_clipboard(self, output: str) -> None:
        """Copy output to clipboard."""
        if output:
            try:
                pyperclip.copy(output)
                print(f"\n✓ Output automatically copied to clipboard.")
            except Exception as e:
                print(f"\n⚠ Failed to copy to clipboard: {e}")
        else:
            print("\n⚠ No output to copy.")

    def _prompt_initial_data_input(self) -> None:
        """Prompt user for initial data input when the tool starts."""
        print("\n" + "=" * 60)
        print("           WELCOME TO TEXT MANIPULATION TOOL")
        print("                 VERSION 2.0.0 | By: lys")
        print("=" * 60)
        
        while True:
            response = input("\nWould you like to input data now? (y/n): ").strip().lower()
            
            if response in ['y', 'yes']:
                print("\nGreat! Let's get your data.")
                self.text = self.input_handler.get_text_input()
                if self.text:
                    print(f"\n✓ Data loaded successfully! ({len(self.text)} characters)")
                    print("You can now select operations from the main menu.")
                break
            elif response in ['n', 'no']:
                print("\nNo problem! You can input data later using the 'Data Input/Management' menu.")
                print("You can also input data when selecting any extraction operation.")
                break
            else:
                print("Please enter 'y' for yes or 'n' for no.")

    def _set_api_key(self, env_var_name: str, service_name: str) -> None:
        """Set an API key for a specific service."""
        print(f"\n{service_name} API Key Configuration")
        print("=" * 40)
        
        # Show current status
        current_key = os.getenv(env_var_name)
        if current_key:
            masked_key = current_key[:8] + "*" * (len(current_key) - 8) if len(current_key) > 8 else "*" * len(current_key)
            print(f"Current key: {masked_key}")
        else:
            print("Current key: Not set")
        
        # Show service information
        if env_var_name == 'IPINFO_API_KEY':
            print(f"\n{service_name} provides IP geolocation and threat intelligence data.")
            print("Free tier: 50,000 requests/month without API key")
            print("Paid tier: Higher limits with API key")
            print("Get your API key at: https://ipinfo.io/signup")
        elif env_var_name == 'VIRUSTOTAL_API_KEY':
            print(f"\n{service_name} provides malware and threat intelligence data.")
            print("Required for IP scanning functionality.")
            print("Get your API key at: https://www.virustotal.com/gui/join-us")
        elif env_var_name == 'ABUSEIPDB_API_KEY':
            print(f"\n{service_name} provides IP abuse and reputation data.")
            print("Required for IP scanning functionality.")
            print("Get your API key at: https://www.abuseipdb.com/register")
        
        print(f"\nEnter your {service_name} API key (or press Enter to skip):")
        api_key = input("> ").strip()
        
        if not api_key:
            print(f"\n{service_name} API key not changed.")
            return
        
        # Validate key format (basic validation)
        if len(api_key) < 10:
            print(f"\n⚠ Warning: API key seems too short. Please verify it's correct.")
        
        # Set the environment variable for current session
        os.environ[env_var_name] = api_key
        
        # Offer to save to .env file
        self._save_api_key_to_env_file(env_var_name, api_key, service_name)
        
        print(f"\n✓ {service_name} API key set successfully for this session!")
        
        # Reinitialize IP scanner to pick up new keys
        if hasattr(self, 'ip_scanner'):
            self.ip_scanner = IPScannerInterface()

    def _save_api_key_to_env_file(self, env_var_name: str, api_key: str, service_name: str) -> None:
        """Save API key to .env file for persistence."""
        save_choice = input(f"\nSave {service_name} API key to .env file for future sessions? (y/n): ").strip().lower()
        
        if save_choice not in ['y', 'yes']:
            print("API key will only be available for this session.")
            return
        
        try:
            env_file_path = '.env'
            env_content = {}
            
            # Read existing .env file if it exists
            if os.path.exists(env_file_path):
                with open(env_file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            env_content[key.strip()] = value.strip()
            
            # Update or add the API key
            env_content[env_var_name] = api_key
            
            # Write back to .env file
            with open(env_file_path, 'w') as f:
                f.write("# API Keys for Text Manipulation Tool\n")
                f.write("# Get your API keys from the respective service providers\n\n")
                
                for key, value in env_content.items():
                    f.write(f"{key}={value}\n")
            
            print(f"✓ {service_name} API key saved to .env file!")
            
        except Exception as e:
            print(f"⚠ Failed to save to .env file: {e}")
            print("The API key is still set for this session.")

    def _show_api_configuration(self) -> None:
        """Display current API configuration status."""
        print("\nCurrent API Configuration")
        print("=" * 40)
        
        # Check each API key
        api_keys = [
            ('IPINFO_API_KEY', 'IPInfo', 'Optional - Enhanced geolocation data'),
            ('VIRUSTOTAL_API_KEY', 'VirusTotal', 'Required - Malware scanning'),
            ('ABUSEIPDB_API_KEY', 'AbuseIPDB', 'Required - IP abuse data')
        ]
        
        for env_var, service, description in api_keys:
            current_key = os.getenv(env_var)
            if current_key:
                masked_key = current_key[:8] + "*" * (len(current_key) - 8) if len(current_key) > 8 else "*" * len(current_key)
                status = f"✓ Configured ({masked_key})"
                color = "\033[92m"  # Green
            else:
                status = "✗ Not configured"
                color = "\033[91m" if 'Required' in description else "\033[93m"  # Red for required, Yellow for optional
            
            reset_color = "\033[0m"
            print(f"{service:12} | {color}{status:25}{reset_color} | {description}")
        
        # Check if .env file exists
        if os.path.exists('.env'):
            print(f"\n✓ .env file exists - API keys will persist across sessions")
        else:
            print(f"\n⚠ No .env file found - API keys are session-only")
        
        # Show usage recommendations
        print(f"\nRecommendations:")
        if not os.getenv('VIRUSTOTAL_API_KEY') or not os.getenv('ABUSEIPDB_API_KEY'):
            print("• Set VirusTotal and AbuseIPDB API keys to use IP scanning features")
        if not os.getenv('IPINFO_API_KEY'):
            print("• Set IPInfo API key for enhanced geolocation data (optional)")

    def _clear_api_keys(self) -> None:
        """Clear all API keys."""
        print("\nClear API Keys")
        print("=" * 20)
        
        confirm = input("Are you sure you want to clear all API keys? (y/n): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("API keys not cleared.")
            return
        
        # Clear from current session
        api_keys = ['IPINFO_API_KEY', 'VIRUSTOTAL_API_KEY', 'ABUSEIPDB_API_KEY']
        cleared_count = 0
        
        for key in api_keys:
            if os.getenv(key):
                del os.environ[key]
                cleared_count += 1
        
        # Ask about .env file
        if os.path.exists('.env'):
            clear_file = input("Also remove API keys from .env file? (y/n): ").strip().lower()
            if clear_file in ['y', 'yes']:
                try:
                    # Read .env file and remove API key lines
                    new_content = []
                    with open('.env', 'r') as f:
                        for line in f:
                            if not any(key in line for key in api_keys):
                                new_content.append(line)
                    
                    # Write back without API keys
                    with open('.env', 'w') as f:
                        f.writelines(new_content)
                    
                    print("✓ API keys removed from .env file")
                except Exception as e:
                    print(f"⚠ Failed to update .env file: {e}")
        
        print(f"✓ Cleared {cleared_count} API keys from current session")
        
        # Reinitialize IP scanner
        if hasattr(self, 'ip_scanner'):
            self.ip_scanner = IPScannerInterface() 