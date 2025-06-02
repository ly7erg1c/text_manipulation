"""
Display management for the text manipulation tool CLI.

This module handles all display-related functionality including menus,
output formatting, and screen management.
"""

import os
import platform

# Initialize colorama for cross-platform color support
try:
    import colorama
    colorama.init(autoreset=True)
except ImportError:
    # Colorama not available, colors will work on Unix-like systems
    pass


class Color:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def display_header(title: str) -> None:
    """
    Display a formatted header with the given title.
    
    Args:
        title: The title to display in the header
    """
    header_length = max(60, len(title) + 20)
    border = "=" * header_length
    padding = (header_length - len(title)) // 2
    
    print(f"\n{Color.CYAN}{border}")
    print(f"{' ' * padding}{title}")
    print(f"{border}{Color.RESET}")


def display_result(message: str, result_type: str = "info") -> None:
    """
    Display a formatted result message.
    
    Args:
        message: The message to display
        result_type: Type of result ('success', 'error', 'warning', 'info')
    """
    color_map = {
        'success': Color.GREEN,
        'error': Color.RED,
        'warning': Color.YELLOW,
        'info': Color.CYAN
    }
    
    color = color_map.get(result_type, Color.RESET)
    print(f"{color}{message}{Color.RESET}")


class DisplayManager:
    """Manages display and formatting for the CLI interface."""
    
    def __init__(self):
        self.is_windows = platform.system().lower() == 'windows'
    
    def clear_screen(self):
        """Clear the terminal screen."""
        if self.is_windows:
            os.system('cls')
        else:
            os.system('clear')
    
    def show_welcome(self):
        """Display the welcome message."""
        print("=" * 60)
        print("           TEXT MANIPULATION TOOL")
        print("=" * 60)
        print("Welcome! This tool helps you extract and manipulate")
        print("various types of data from text including:")
        print("• Cryptographic hashes (MD5, SHA1, SHA256)")
        print("• Network data (IPv4 addresses, URLs)")
        print("• File references (executables)")
        print("• Text formatting utilities")
        print("=" * 60)
    
    def show_main_menu(self):
        """Display the main menu."""
        print("\n" + "=" * 50)
        print("                 MAIN MENU")
        print("=" * 50)
        print("1) Find Hashes")
        print("2) Find IPv4 Addresses")
        print("3) Convert Newlines to Spaces")
        print("4) Remove Blank Lines")
        print("5) Find URLs")
        print("7) Find Executable Files")
        print("8) Exit")
        print("9) Clear Terminal")
        print("10) Input New Data")
        print("11) Copy Previous Output to Clipboard")
        print("=" * 50)
    
    def show_hash_submenu(self):
        """Display the hash extraction submenu."""
        print("\n" + "-" * 40)
        print("            HASH FINDER")
        print("-" * 40)
        print("1) Find SHA256 Hashes")
        print("2) Find SHA1 Hashes")
        print("3) Find MD5 Hashes")
        print("4) Copy Previous Output to Clipboard")
        print("5) Back to Main Menu")
        print("-" * 40)
    
    def show_uri_submenu(self):
        """Display the URI extraction submenu."""
        print("\n" + "-" * 40)
        print("            URL FINDER")
        print("-" * 40)
        print("1) Find URLs")
        print("2) Find URLs [DEFANGED]")
        print("3) Clear Terminal")
        print("4) Copy Previous Output to Clipboard")
        print("5) Return to Main Menu")
        print("-" * 40)
    
    def show_file_finder_submenu(self):
        """Display the file finder submenu."""
        print("\n" + "-" * 40)
        print("           FILE FINDER")
        print("-" * 40)
        print("1) Find Executable Files")
        print("2) Return to Main Menu")
        print("3) Copy Previous Output to Clipboard")
        print("9) Clear Terminal")
        print("-" * 40)
    
    def show_output_header(self):
        """Display the output header."""
        print("\n" + "=" * 50)
        print("                OUTPUT")
        print("=" * 50)
    
    def show_separator(self):
        """Display a separator line."""
        print("-" * 50)


# Alias for backward compatibility and test compatibility
Display = DisplayManager