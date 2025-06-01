"""
Input handling utilities for the text manipulation tool.

This module provides functionality for getting text input from various sources
including direct user input and file reading.
"""

import os
from typing import Optional


class InputHandler:
    """Handles various types of text input for the application."""
    
    def get_text_input(self) -> str:
        """
        Get text input from user, either directly or from a file.
        
        Returns:
            The text content to be processed
        """
        while True:
            print("\nInput Options:")
            print("I - Direct text input")
            print("F - Read from file")
            choice = input("Enter your choice (I/F): ").upper().strip()
            
            if choice == 'I':
                return self._get_direct_input()
            elif choice == 'F':
                text = self._get_file_input()
                if text is not None:
                    return text
            else:
                print("Invalid option. Please enter 'I' for input or 'F' for file.")
    
    def _get_direct_input(self) -> str:
        """
        Get text input directly from the user.
        
        Returns:
            The text entered by the user
        """
        print("\nEnter your text (type 'DONE!' on a new line or press Ctrl+D/Ctrl+Z to finish):")
        lines = []
        
        while True:
            try:
                line = input()
                if line.strip().upper() == "DONE!":
                    break
                lines.append(line)
            except EOFError:
                break
        
        return '\n'.join(lines)
    
    def _get_file_input(self) -> Optional[str]:
        """
        Get text input from a file.
        
        Returns:
            The content of the file, or None if file couldn't be read
        """
        file_path = input("Enter the file path: ").strip()
        
        try:
            # Handle relative and absolute paths
            if not os.path.isabs(file_path):
                # Try relative to current working directory
                if not os.path.exists(file_path):
                    print(f"File not found: {file_path}")
                    return None
            
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                print(f"Successfully loaded file: {file_path}")
                print(f"File size: {len(content)} characters")
                return content
                
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return None
        except PermissionError:
            print(f"Permission denied: {file_path}")
            return None
        except UnicodeDecodeError:
            print(f"Unable to decode file as UTF-8: {file_path}")
            try:
                with open(file_path, 'r', encoding='latin-1') as file:
                    content = file.read()
                    print("File loaded using latin-1 encoding")
                    return content
            except Exception as e:
                print(f"Failed to read file with alternative encoding: {e}")
                return None
        except Exception as e:
            print(f"Error reading file: {e}")
            return None 