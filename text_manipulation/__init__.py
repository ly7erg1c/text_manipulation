"""
Text Manipulation Tool

A command-line utility for extracting and manipulating various types of data from text.
Supports extraction of hashes, IP addresses, URLs, and executable files.
"""

__version__ = "1.0.0"
__author__ = "lys"

from .core.extractors import HashExtractor, NetworkExtractor, FileExtractor, TextManipulator
from .cli.interface import TextManipulationCLI

__all__ = [
    "HashExtractor",
    "NetworkExtractor", 
    "FileExtractor",
    "TextManipulator",
    "TextManipulationCLI"
] 