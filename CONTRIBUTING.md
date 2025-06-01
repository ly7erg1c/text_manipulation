# Contributing to Text Manipulation Tool

Thank you for your interest in contributing to the Text Manipulation Tool! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Contributions](#making-contributions)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct:

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Maintain a professional attitude

## Getting Started

### Types of Contributions

We welcome various types of contributions:

1. **Bug Reports** - Help us find and fix issues
2. **Feature Requests** - Suggest new functionality
3. **Code Contributions** - Implement features or fix bugs
4. **Documentation** - Improve docs, add examples
5. **Testing** - Add test cases, improve coverage

### Before You Start

1. Check existing issues to avoid duplicates
2. Discuss major changes in an issue first
3. Fork the repository
4. Create a feature branch

## Development Setup

### Prerequisites

- Python 3.7 or higher
- Git
- Text editor or IDE (VS Code, PyCharm, etc.)

### Setup Steps

```bash
# 1. Fork and clone the repository
git clone https://github.com/yourusername/text-manipulation-tool.git
cd text-manipulation-tool

# 2. Create a virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Install in development mode
pip install -e .

# 6. Test the installation
python main.py
```

## Making Contributions

### Project Structure

Understanding the project structure will help you contribute effectively:

```
text_manipulation/
├── core/
│   └── extractors.py    # Core data extraction logic
└── cli/
    ├── interface.py     # Main CLI interface
    ├── input_handler.py # Input processing
    └── display.py       # Display formatting
```

### Adding New Features

#### Adding a New Extractor

1. **Add the extraction logic** in `text_manipulation/core/extractors.py`:

```python
class NetworkExtractor:
    @staticmethod
    def extract_emails(text: str) -> Set[str]:
        """Extract email addresses from text."""
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return set(re.findall(pattern, text))
```

2. **Add CLI integration** in `text_manipulation/cli/interface.py`:

```python
def _handle_email_extraction(self):
    """Handle email address extraction."""
    result = self.network_extractor.extract_emails(self.text)
    self._display_and_store_output(result)
```

3. **Add menu options** in `text_manipulation/cli/display.py`:

```python
def show_network_submenu(self):
    """Display the network extraction submenu."""
    print("1) Find IPv4 Addresses")
    print("2) Find URLs")
    print("3) Find Email Addresses")  # Add this
```

4. **Update documentation** in README.md and add docstrings

#### Adding New Text Manipulations

Add methods to the `TextManipulator` class:

```python
class TextManipulator:
    @staticmethod
    def extract_lines_with_pattern(text: str, pattern: str) -> str:
        """Extract lines containing a specific pattern."""
        lines = text.split('\n')
        matching_lines = [line for line in lines if re.search(pattern, line)]
        return '\n'.join(matching_lines)
```

### Improving Existing Features

- **Performance optimizations**: Improve regex patterns or algorithm efficiency
- **Error handling**: Add better error messages and exception handling
- **User experience**: Improve menu navigation or add shortcuts
- **Cross-platform compatibility**: Ensure features work on all supported platforms

## Code Style Guidelines

### Python Code Style

Follow PEP 8 with these specific guidelines:

```python
# Use type hints
def extract_data(text: str) -> Set[str]:
    """Extract specific data from text."""
    pass

# Use descriptive variable names
ip_addresses = extractor.extract_ipv4(text)
sha256_hashes = extractor.extract_sha256(text)

# Keep functions focused and small
def validate_input(text: str) -> bool:
    """Validate that input text is not empty."""
    return bool(text and text.strip())

# Use docstrings for all public methods
def extract_urls(text: str) -> Set[str]:
    """
    Extract URLs from text.
    
    Args:
        text: The input text to search
        
    Returns:
        Set of unique URLs found
        
    Raises:
        ValueError: If text is None
    """
```

### Documentation Style

- Use clear, concise language
- Provide examples where helpful
- Keep documentation up to date with code changes
- Use proper markdown formatting

## Testing

### Manual Testing

Test your changes with various inputs:

```bash
# Test basic functionality
python main.py

# Test with sample files
echo "test@example.com and 192.168.1.1" > test_input.txt
python main.py  # Use file input option
```

### Test Cases to Consider

1. **Empty input**: How does your feature handle empty strings?
2. **Invalid input**: What happens with malformed data?
3. **Large input**: Does it perform well with large files?
4. **Edge cases**: Unicode characters, special symbols, etc.
5. **Cross-platform**: Test on different operating systems

### Adding Automated Tests

While the project doesn't currently have a test suite, you can help by:

1. Creating a `tests/` directory
2. Adding unit tests for extractor classes
3. Adding integration tests for CLI functionality
4. Setting up continuous integration

Example test structure:

```python
import unittest
from text_manipulation.core.extractors import HashExtractor

class TestHashExtractor(unittest.TestCase):
    def test_extract_md5(self):
        text = "Hash: 5d41402abc4b2a76b9719d911017c592"
        result = HashExtractor.extract_md5(text)
        self.assertEqual(result, {"5d41402abc4b2a76b9719d911017c592"})
```

## Documentation

### Types of Documentation

1. **Code comments**: Explain complex logic
2. **Docstrings**: Document all public methods
3. **README updates**: Keep the main documentation current
4. **Examples**: Add usage examples
5. **API documentation**: Document public interfaces

### Documentation Standards

- Use clear, simple language
- Provide practical examples
- Keep it up to date
- Include error conditions and edge cases

## Submitting Changes

### Before Submitting

1. **Test thoroughly**: Ensure your changes work as expected
2. **Check documentation**: Update docs if needed
3. **Review your code**: Look for potential improvements
4. **Commit messages**: Write clear, descriptive commit messages

### Commit Message Format

```
feat: add email extraction functionality

- Add extract_emails method to NetworkExtractor
- Update CLI to support email extraction
- Add email submenu and display options
- Update documentation with email examples
```

Use these prefixes:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `refactor:` for code refactoring
- `test:` for adding tests
- `chore:` for maintenance tasks

### Pull Request Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/email-extraction
   ```

2. **Make your changes and commit**:
   ```bash
   git add .
   git commit -m "feat: add email extraction functionality"
   ```

3. **Push to your fork**:
   ```bash
   git push origin feature/email-extraction
   ```

4. **Create a pull request** with:
   - Clear title and description
   - Link to related issues
   - Screenshots/examples if applicable
   - Testing notes

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring

## Testing
- [ ] Tested manually
- [ ] Added test cases
- [ ] All existing tests pass

## Screenshots/Examples
If applicable, add screenshots or example outputs

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed the code
- [ ] Documentation updated
- [ ] No new warnings/errors
```

## Getting Help

If you need help:

1. **Check the documentation**: README.md and code comments
2. **Search existing issues**: Someone might have asked the same question
3. **Open a discussion**: For general questions about contributing
4. **Open an issue**: For specific bugs or feature requests

## Recognition

Contributors will be recognized in:

- The README.md file
- Release notes
- Hall of fame (if we create one)

Thank you for contributing to the Text Manipulation Tool! Your efforts help make this tool better for everyone. 