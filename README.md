# Text Manipulation Tool

A command-line utility for extracting and manipulating various types of data from text. This tool is designed for cybersecurity professionals, developers, and anyone who needs to quickly extract structured data from unstructured text.

**Important Privacy Notice**: This tool only queries existing threat intelligence data from external APIs. No user data, hashes, IP addresses, or URLs are ever posted or submitted to VirusTotal or AbuseIPDB APIs. The tool performs read-only queries against their existing intelligence databases. If information about a specific artifact is not present in their intelligence corpus, the tool will return no result for that artifact.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Quick Installation](#quick-installation)
  - [Development Installation](#development-installation)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Input Options](#input-options)
  - [Menu Navigation](#menu-navigation)
  - [Enhanced Features](#enhanced-features)
  - [Examples](#examples)
- [API Configuration](#api-configuration)
  - [Supported Services](#supported-services)
  - [Setting Up API Keys](#setting-up-api-keys)
  - [API Key Features](#api-key-features)
- [Architecture](#architecture)
  - [Key Components](#key-components)
  - [Menu System Design](#menu-system-design)
- [Contributing](#contributing)
  - [Types of Contributions](#types-of-contributions)
  - [Development Setup](#development-setup)
  - [Adding New Extractors](#adding-new-extractors)
  - [Adding New Menu Categories](#adding-new-menu-categories)
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Performance Considerations](#performance-considerations)
- [License](#license)

## Features

- **Hash Extraction**: Extract cryptographic hashes (MD5, SHA1, SHA256) from text
- **Network Data Extraction**: Find IPv4 addresses and URLs (with defanging support)
- **IP Threat Intelligence**: Scan IP addresses for threat intelligence (read-only queries)
- **URL Threat Intelligence**: Scan URLs for malware and reputation analysis via VirusTotal (read-only queries)
- **Polling Mode**: Automatically watch clipboard for hashes, IPs, and URLs with real-time threat intelligence analysis
- **File Reference Extraction**: Locate executable file references (.exe, .bat, .cmd, .sh, .bin)
- **Text Manipulation**: Convert newlines to spaces, remove blank lines
- **Data Management**: View text statistics, clear text, manage input data
- **Cross-platform**: Works on Windows, Linux, and macOS
- **Clipboard Integration**: Copy results directly to clipboard
- **File Input Support**: Process text from files or direct input
- **Organized Menu System**: Logical categorization with sub-menus for better navigation

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

The tool features an organized menu system with logical categories:

#### Main Menu
```
============================================================
           TEXT MANIPULATION TOOL
============================================================

Select a category:
1. Hash Extraction
2. Network Analysis
3. File Operations
4. Text Manipulation
5. Data Input/Management
6. API Configuration
7. Polling Mode
0. Exit
```

#### Sub-Menu Examples

**Hash Extraction Menu:**
```
============================================================
           HASH EXTRACTION
============================================================

Select an option:
1. Extract SHA256 hashes
2. Extract SHA1 hashes
3. Extract MD5 hashes
0. Back to main menu
```

**Network Analysis Menu:**
```
============================================================
           NETWORK ANALYSIS
============================================================

Select an option:
1. Extract IPv4 addresses
2. Extract URLs (with http/https)
3. Extract and defang URLs
4. IP Address Threat Intelligence Scanner
5. URL Threat Intelligence Scanner
0. Back to main menu
```

**Data Input/Management Menu:**
```
============================================================
           DATA INPUT/MANAGEMENT
============================================================

Select an option:
1. Input new text
2. View current text info
3. Clear current text
0. Back to main menu
```

**API Configuration Menu:**
```
============================================================
           API CONFIGURATION
============================================================

Select an option:
1. Set IPInfo API Key
2. Set VirusTotal API Key
3. Set AbuseIPDB API Key
4. View current API configuration
5. Clear all API keys
0. Back to main menu
```

**Polling Mode Menu:**
```
============================================================
       Polling Mode
============================================================

Select an option:
1. Start Polling mode
2. Configure polling interval
3. Check API configuration status
4. Help & information
0. Back to main menu
```

### Enhanced Features

#### Polling Mode
The clipboard monitor automatically detects and analyzes security indicators when you copy them:

- **Real-time Detection**: Monitors clipboard for SHA hashes (MD5, SHA1, SHA256), IP addresses, and URLs
- **Automatic Analysis**: Instantly analyzes detected IOCs using threat intelligence APIs
- **Streaming Results**: Clean, formatted output streamed to terminal in real-time
- **Session Statistics**: Tracks analyzed IOCs and malicious findings
- **Configurable Polling**: Adjustable monitoring interval (0.5-60 seconds)
- **Smart Deduplication**: Only analyzes each IOC once per session

Example clipboard monitoring output:
```
[14:25:30] New clipboard content detected...
   Found 1 new hash(es)

HASH ANALYSIS: 5d41402abc4b2a76b9719d911017c592
   ────────────────────────────────────────────────────────
   Status: [CLEAN] Clean
   Detections: 0/73 engines
   Type: Text file
   Name: hello.txt
   Size: 5.00 KB
```

#### Text Information Display
View detailed statistics about your loaded text:
- Character count
- Line count  
- Word count
- Non-empty lines count
- Preview of first few lines

#### Smart Text Handling
- Automatic prompting for text input when needed
- Confirmation dialogs for destructive operations
- Better empty result handling with informative messages

### Examples

#### Clipboard Monitoring Workflow

1. **Start Monitoring**: Select option 7 from main menu, then option 1
2. **Copy IOCs**: Copy any text containing hashes or IP addresses
3. **Watch Analysis**: See real-time threat intelligence results
4. **Stop Monitoring**: Press Ctrl+C to stop and see session summary

```
SESSION SUMMARY
Duration: 00:15:42
Polling cycles: 471
Hashes analyzed: 12
IPs analyzed: 8
URLs analyzed: 5
Malicious hashes: 3
Malicious IPs: 1
Malicious URLs: 2
```

#### Finding Hashes

Input text containing hashes:
```
Here are some hashes:
5d41402abc4b2a76b9719d911017c592
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The tool will extract:
- MD5: `5d41402abc4b2a76b9719d911017c592`
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

#### IP Threat Intelligence Scanning

The tool includes an integrated IP scanner that can:
- Check multiple threat intelligence sources using read-only API queries
- Analyze IP reputation and geolocation from existing databases
- Provide detailed threat reports based on historical data
- Support bulk IP scanning
- **Privacy Note**: No IP addresses are submitted to external services; only queries against existing intelligence databases are performed

#### URL Threat Intelligence Scanning

The tool includes URL analysis capabilities that can:
- Check URLs against VirusTotal's existing database using read-only queries
- Analyze URL reputation and categories from historical data
- Detect malicious and suspicious URLs based on existing intelligence
- Process single URLs or bulk lists
- Extract URLs from clipboard content
- **Privacy Note**: No URLs are submitted for analysis; only queries against existing VirusTotal intelligence corpus are performed

Example URL scan output:
```
URL: https://malicious-example.com
  VirusTotal: [MALICIOUS] Malicious
    Detections: 15/89 engines
    Categories: malware, phishing
    Threats: Trojan.Generic, Phishing.Scam
```

### API Configuration

The tool supports integration with multiple threat intelligence services through read-only API queries. You can configure API keys through the interactive menu or environment variables.

**Important**: This tool only performs read-only queries against existing threat intelligence databases. No user data is ever submitted, posted, or uploaded to any external services.

#### Supported Services

1. **IPInfo** (Optional)
   - Provides enhanced IP geolocation and threat intelligence data through read-only queries
   - Free tier: 50,000 requests/month without API key
   - Enhanced features with paid API key
   - Get your API key at: https://ipinfo.io/signup

2. **VirusTotal** (Required for IP scanning and URL analysis)
   - Provides malware and threat intelligence data through read-only database queries
   - Required for IP scanning and URL analysis functionality
   - **Privacy Guarantee**: Only performs GET requests to query existing data; never submits user data
   - Get your API key at: https://www.virustotal.com/gui/join-us

3. **AbuseIPDB** (Required for IP scanning)
   - Provides IP abuse and reputation data through read-only database queries
   - Required for IP scanning functionality
   - **Privacy Guarantee**: Only performs GET requests to query existing data; never submits user data
   - Get your API key at: https://www.abuseipdb.com/register

#### Setting Up API Keys

##### Interactive Configuration (Recommended)

1. Run the tool: `python main.py`
2. Select "6. API Configuration" from the main menu
3. Choose the service you want to configure
4. Enter your API key when prompted
5. Choose whether to save to `.env` file for persistence

##### Manual Configuration

Create a `.env` file in the project root:

```bash
# Copy .env.example to .env and add your keys
cp .env.example .env
```

Edit the `.env` file with your API keys:

```bash
# IPInfo API Key (Optional - enhances geolocation data)
IPINFO_API_KEY=your_ipinfo_api_key_here

# VirusTotal API Key (Required for IP scanning and URL analysis)
# Used only for read-only queries against existing database
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# AbuseIPDB API Key (Required for IP scanning)
# Used only for read-only queries against existing database
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

#### API Key Features

- **Session Management**: Keys set through the menu are available for the current session
- **Persistent Storage**: Option to save keys to `.env` file for future sessions
- **Masked Display**: API keys are partially hidden when viewing configuration
- **Validation**: Basic format validation when setting keys
- **Secure Handling**: Keys are stored securely and never logged
- **Read-Only Usage**: All API keys are used exclusively for read-only database queries

```

### Key Components

- **HashExtractor**: Handles all hash-related extraction (MD5, SHA1, SHA256)
- **NetworkExtractor**: Manages IP addresses and URL extraction with defanging
- **FileExtractor**: Extracts file references from text
- **TextManipulator**: Provides text transformation utilities
- **TextManipulationCLI**: Main CLI interface with organized sub-menu system
- **InputHandler**: Manages text input from various sources
- **DisplayManager**: Handles all display formatting and menus
- **IPScannerInterface**: Dedicated interface for IP threat intelligence scanning
- **URLScannerInterface**: Dedicated interface for URL threat intelligence scanning

### Menu System Design

The refactored menu system provides:

1. **Logical Organization**: Related functions grouped together
2. **Easy Navigation**: Clear back/exit options in every menu
3. **Scalability**: Easy to add new categories and functions
4. **User-Friendly**: Intuitive flow and helpful prompts
5. **Enhanced UX**: Better error handling and user feedback

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

2. Add menu handling in the appropriate sub-menu in `text_manipulation/cli/interface.py`
3. Update the corresponding display menu method
4. Add comprehensive docstrings and type hints
5. Update documentation

### Adding New Menu Categories

To add a new menu category:

1. Create a new `display_[category]_menu()` method
2. Create a corresponding `_handle_[category]_menu()` method
3. Add the category to the main menu display
4. Add the menu handler to the main run loop
5. Follow the established pattern for navigation and user feedback

## Dependencies

- **pyperclip**: Clipboard operations (cross-platform)
- **requests**: HTTP requests for IP scanning
- **python-dotenv**: Environment variable management
- **aiohttp**: Asynchronous HTTP client for IP scanning
- **tenacity**: Retry logic for API calls
- **re**: Regular expressions (built-in)
- **os**: Operating system interface (built-in)
- **typing**: Type hints (built-in in Python 3.5+)

## Configuration

The tool supports configuration through environment variables:

```bash
# Copy the example configuration
cp .env.example .env

# Edit configuration as needed
# Set API keys for threat intelligence services
# Configure timeout and retry settings
```

## Troubleshooting

### Common Issues

1. **Clipboard not working in virtualized environments**:
   - This is a known limitation in some virtualized environments
   - Results are still displayed on screen for manual copying

2. **Module not found errors**:
   - Ensure you're running from the correct directory
   - Check that all files are in the right locations
   - Verify virtual environment is activated if using one

3. **File encoding issues**:
   - The tool automatically tries UTF-8 and falls back to latin-1
   - For other encodings, convert the file first

4. **API timeout issues with IP scanning**:
   - Check internet connection
   - Verify API keys in .env file
   - Some threat intelligence services may be rate-limited

### Performance Considerations

- For very large files (>100MB), consider splitting the input
- Regular expressions are optimized but may be slow on extremely long lines
- Memory usage scales with input size
- IP scanning performance depends on network connectivity and API response times


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
