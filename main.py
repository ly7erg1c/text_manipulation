#!/usr/bin/env python3
"""
Text Manipulation Tool - Main Entry Point

A command-line utility for extracting and manipulating various types of data from text.
Supports extraction of hashes, IP addresses, URLs, and executable files.

Usage:
    python main.py

Author: Text Manipulation Tool Contributors
Version: 1.0.0
"""

from text_manipulation.cli.interface import TextManipulationCLI


def main():
    """Main entry point for the text manipulation tool."""
    try:
        cli = TextManipulationCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\nExiting... Thank you for using the Text Manipulation Tool!")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        print("Please report this issue if it persists.")


if __name__ == "__main__":
    main() 