"""
Command-line interface for the text manipulation tool.

This module provides the interactive CLI for the text manipulation tool,
including menu systems and user input handling.
"""

import os
from typing import Optional, Set, Union
import pyperclip

from ..core.extractors import HashExtractor, NetworkExtractor, FileExtractor, TextManipulator
from .input_handler import InputHandler
from .display import DisplayManager
from .ip_scanner_interface import IPScannerInterface


class TextManipulationCLI:
    """Main CLI interface for the text manipulation tool."""
    
    def __init__(self):
        self.text: str = ""
        self.previous_output: str = ""
        self.input_handler = InputHandler()
        self.display = DisplayManager()
        self.hash_extractor = HashExtractor()
        self.network_extractor = NetworkExtractor()
        self.file_extractor = FileExtractor()
        self.text_manipulator = TextManipulator()
        self.ip_scanner = IPScannerInterface()
    
    def display_main_menu(self) -> None:
        """Display main menu with categories."""
        print("\n" + "=" * 60)
        print("           TEXT MANIPULATION TOOL")
        print("=" * 60)
        print("\nSelect a category:")
        print("1. Hash Extraction")
        print("2. Network Analysis")
        print("3. File Operations") 
        print("4. Text Manipulation")
        print("5. Data Input/Management")
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
        print("0. Back to main menu")

    def display_network_menu(self) -> None:
        """Display network analysis submenu."""
        print("\n" + "=" * 60)
        print("           NETWORK ANALYSIS")
        print("=" * 60)
        print("\nSelect an option:")
        print("1. Extract IPv4 addresses")
        print("2. Extract URLs (with http/https)")
        print("3. Extract and defang URLs")
        print("4. IP Address Threat Intelligence Scanner")
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
                self._handle_file_menu()
            elif choice == '4':
                self._handle_text_menu()
            elif choice == '5':
                self._handle_data_menu()
            else:
                print("Invalid option, please try again.")

    def _handle_hash_menu(self) -> None:
        """Handle hash extraction submenu."""
        while True:
            self.display_hash_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '0':
                break
            elif choice in ['1', '2', '3']:
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
            elif choice == '4':
                self.display.clear_screen()
                self.ip_scanner.run()
                input("\nPress Enter to continue...")
            elif choice in ['1', '2', '3']:
                if not self._ensure_text_available():
                    continue
                    
                if choice == '1':
                    result = self.network_extractor.extract_ipv4(self.text)
                    self._display_and_store_output(result)
                elif choice == '2':
                    result = self.network_extractor.extract_urls(self.text)
                    self._display_and_store_output(result)
                elif choice == '3':
                    result = self.network_extractor.defang_urls(self.text)
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
                self.text = self.input_handler.get_text_input()
                print("\nText input updated. You can now perform operations on the new text.")
                input("\nPress Enter to continue...")
            elif choice == '2':
                self._show_text_info()
                input("\nPress Enter to continue...")
            elif choice == '3':
                self._clear_text()
                input("\nPress Enter to continue...")
            else:
                print("Invalid option, please try again.")

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