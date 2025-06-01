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
    
    def run(self):
        """Start the CLI application."""
        self.display.show_welcome()
        self.text = self.input_handler.get_text_input()
        self._main_menu()
    
    def _main_menu(self):
        """Display and handle the main menu."""
        while True:
            self.display.show_main_menu()
            choice = input("Enter your choice: ")
            
            if choice == "1":
                self.display.clear_screen()
                self._hash_submenu()
            elif choice == "2":
                self._handle_ipv4_extraction()
            elif choice == "3":
                self._handle_newline_to_space()
            elif choice == "4":
                self._handle_remove_blank_lines()
            elif choice == "5":
                self.display.clear_screen()
                self._uri_submenu()
            elif choice == "7":
                self.display.clear_screen()
                self._file_finder_submenu()
            elif choice == "8":
                self.display.clear_screen()
                break
            elif choice == "9":
                self.display.clear_screen()
            elif choice == "10":
                self.text = self.input_handler.get_text_input()
            elif choice == "11":
                self._copy_to_clipboard(self.previous_output)
            else:
                print("Invalid option, please try again.")
    
    def _hash_submenu(self):
        """Handle the hash extraction submenu."""
        while True:
            self.display.show_hash_submenu()
            choice = input("Enter your choice: ")
            
            if choice == "1":
                result = self.hash_extractor.extract_sha256(self.text)
                self._display_and_store_output(result)
            elif choice == "2":
                result = self.hash_extractor.extract_sha1(self.text)
                self._display_and_store_output(result)
            elif choice == "3":
                result = self.hash_extractor.extract_md5(self.text)
                self._display_and_store_output(result)
            elif choice == "4":
                self._copy_to_clipboard(self.previous_output)
            elif choice == "5":
                self.display.clear_screen()
                break
            else:
                print("Invalid option, please try again.")
    
    def _uri_submenu(self):
        """Handle the URI extraction submenu."""
        while True:
            self.display.show_uri_submenu()
            choice = input("Enter your choice: ")
            
            if choice == "1":
                result = self.network_extractor.extract_urls(self.text)
                self._display_and_store_output(result)
            elif choice == "2":
                result = self.network_extractor.defang_urls(self.text)
                self._display_and_store_output(result)
            elif choice == "3":
                self.display.clear_screen()
            elif choice == "4":
                self._copy_to_clipboard(self.previous_output)
            elif choice == "5":
                break
            else:
                print("Invalid option, please try again.")
    
    def _file_finder_submenu(self):
        """Handle the file finder submenu."""
        while True:
            self.display.show_file_finder_submenu()
            choice = input("Enter your choice: ")
            
            if choice == "1":
                result = self.file_extractor.extract_executables(self.text)
                self._display_and_store_output(result)
            elif choice == "2":
                self.display.clear_screen()
                break
            elif choice == "3":
                self._copy_to_clipboard(self.previous_output)
            elif choice == "9":
                self.display.clear_screen()
            else:
                print("Invalid option, please try again.")
    
    def _handle_ipv4_extraction(self):
        """Handle IPv4 address extraction."""
        result = self.network_extractor.extract_ipv4(self.text)
        self._display_and_store_output(result)
    
    def _handle_newline_to_space(self):
        """Handle newline to space conversion."""
        result = self.text_manipulator.newline_to_space(self.text)
        self.previous_output = result
        self.display.show_output_header()
        print(result)
    
    def _handle_remove_blank_lines(self):
        """Handle blank line removal."""
        result = self.text_manipulator.remove_blank_lines(self.text)
        self.previous_output = result
        self.display.show_output_header()
        print(result)
    
    def _display_and_store_output(self, output: Union[Set[str], str]):
        """Display output and store it for clipboard operations."""
        self.display.clear_screen()
        self.display.show_output_header()
        
        if isinstance(output, set):
            for item in output:
                print(item)
            self.previous_output = '\n'.join(output)
        else:
            print(output)
            self.previous_output = output
    
    def _copy_to_clipboard(self, output: str):
        """Copy output to clipboard."""
        if output:
            try:
                pyperclip.copy(output)
                print("Output copied to clipboard.")
            except Exception as e:
                print(f"Failed to copy to clipboard: {e}")
        else:
            print("No output to copy.") 