# Text Manipulation Tool

A command-line utility for extracting and manipulating various types of data from text. This tool is designed for cybersecurity professionals, developers, and anyone who needs to quickly extract structured data from unstructured text.

## Features

- **Hash Extraction**: Extract cryptographic hashes (MD5, SHA1, SHA256) from text
- **Network Data Extraction**: Find IPv4 addresses and URLs (with defanging support)
- **File Reference Extraction**: Locate executable file references (.exe, .bat, .cmd, .sh, .bin)
- **Text Manipulation**: Convert newlines to spaces, remove blank lines
- **Cross-platform**: Works on Windows, Linux, and macOS
- **Clipboard Integration**: Copy results directly to clipboard
- **File Input Support**: Process text from files or direct input

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/text-manipulation-tool.git
cd text-manipulation-tool

# Install dependencies
pip install -r requirements.txt

# Run the tool
python main.py
```

### Development Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/text-manipulation-tool.git
cd text-manipulation-tool

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install in development mode
pip install -e .
```

## Usage

### Basic Usage

Run the tool with:

```bash
python main.py
```

### Input Options

The tool supports two input methods:

1. **Direct Input**: Type or paste text directly into the terminal
2. **File Input**: Read text from a file

### Menu Navigation

The tool provides an interactive menu system:

```
=================== MAIN MENU ===================
1) Find Hashes
2) Find IPv4 Addresses  
3) Convert Newlines to Spaces
4) Remove Blank Lines
5) Find URLs
7) Find Executable Files
8) Exit
9) Clear Terminal
10) Input New Data
11) Copy Previous Output to Clipboard
================================================
```

### Examples

#### Finding Hashes

Input text containing hashes:
```
Here are some hashes:
5d41402abc4b2a76b9719d911017c592
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The tool will extract:
- MD5: `5d41402abc4b2a76b9719d911017c592`, `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`
- SHA1: `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`
- SHA256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

#### Finding Network Data

Input text with network information:
```
Connect to 192.168.1.1 or visit https://example.com for more info.
Also check http://test.org and 10.0.0.1
```

Results:
- IPv4 addresses: `192.168.1.1`, `10.0.0.1`
- URLs: `https://example.com`, `http://test.org`
- Defanged URLs: `https://example[.]com`, `http://test[.]org`

#### Finding Executable Files

Input text with file references:
```
Run setup.exe or execute install.bat
Also found: malware.exe, script.sh, and tool.bin
```

Results:
- Executables: `setup.exe`, `install.bat`, `malware.exe`, `script.sh`, `tool.bin`

## Architecture

The project has been refactored into a modular, contributor-friendly structure:

```
text-manipulation-tool/
├── text_manipulation/           # Main package
│   ├── __init__.py             # Package initialization
│   ├── core/                   # Core functionality
│   │   ├── __init__.py
│   │   └── extractors.py       # Data extraction classes
│   └── cli/                    # Command-line interface
│       ├── __init__.py
│       ├── interface.py        # Main CLI interface
│       ├── input_handler.py    # Input handling
│       └── display.py          # Display management
├── main.py                     # Entry point
├── requirements.txt            # Dependencies
├── setup.py                   # Package setup
├── README.md                  # This file
├── CONTRIBUTING.md            # Contribution guidelines
└── LICENSE                    # License file
```

### Key Components

- **HashExtractor**: Handles all hash-related extraction (MD5, SHA1, SHA256)
- **NetworkExtractor**: Manages IP addresses and URL extraction
- **FileExtractor**: Extracts file references from text
- **TextManipulator**: Provides text transformation utilities
- **TextManipulationCLI**: Main CLI interface and menu system
- **InputHandler**: Manages text input from various sources
- **DisplayManager**: Handles all display formatting and menus

## Contributing

We welcome contributions! Here are ways you can help:

### Types of Contributions

1. **Bug Reports**: Found a bug? Please open an issue
2. **Feature Requests**: Have an idea? We'd love to hear it
3. **Code Contributions**: Bug fixes, new features, performance improvements
4. **Documentation**: Improve docs, add examples, fix typos
5. **Testing**: Add test cases, improve test coverage

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test your changes
5. Submit a pull request

### Adding New Extractors

To add a new extractor (e.g., for email addresses):

1. Add methods to the appropriate class in `text_manipulation/core/extractors.py`:
```python
class NetworkExtractor:
    @staticmethod
    def extract_emails(text: str) -> Set[str]:
        """Extract email addresses from text."""
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return set(re.findall(pattern, text))
```

2. Add menu options in `text_manipulation/cli/interface.py`
3. Add display methods in `text_manipulation/cli/display.py`
4. Update documentation

### Code Style

- Follow PEP 8 guidelines
- Use type hints where possible
- Add docstrings to all public methods
- Keep functions focused and small
- Use descriptive variable names

### Testing

```bash
# Run basic functionality test
python main.py

# Test with sample data
echo "Test hash: 5d41402abc4b2a76b9719d911017c592" | python main.py
```

## Dependencies

- **pyperclip**: Clipboard operations (cross-platform)
- **re**: Regular expressions (built-in)
- **os**: Operating system interface (built-in)
- **platform**: Platform-specific utilities (built-in)
- **typing**: Type hints (built-in in Python 3.5+)

## Troubleshooting

### Common Issues

1. **Clipboard not working in virtualized environments**:
   - This is a known limitation mentioned in the original TODO
   - Consider using file output as an alternative

2. **Module not found errors**:
   - Ensure you're running from the correct directory
   - Check that all files are in the right locations

3. **File encoding issues**:
   - The tool automatically tries UTF-8 and falls back to latin-1
   - For other encodings, convert the file first

### Performance Considerations

- For very large files (>100MB), consider splitting the input
- Regular expressions are optimized but may be slow on extremely long lines
- Memory usage scales with input size

## Roadmap

Future improvements (from original TODO and new ideas):

- [ ] Add help function and command-line arguments
- [ ] Implement multi-threading for better performance
- [ ] Add more hash types (SHA384, SHA512, etc.)
- [ ] IPv6 address support
- [ ] Email address extraction
- [ ] Phone number extraction
- [ ] JSON/XML output formats
- [ ] Configuration file support
- [ ] Plugin system for custom extractors
- [ ] GUI version
- [ ] API mode for integration with other tools

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
