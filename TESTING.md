# Testing Infrastructure Documentation

This document describes the comprehensive testing infrastructure for the Text Manipulation Tool project.

## Overview

The testing infrastructure provides:
- **Unit tests** for individual components
- **Integration tests** for component interactions
- **End-to-end tests** for complete workflows
- **Code coverage reporting**
- **Performance testing**
- **API mocking and testing**
- **CLI testing**
- **Multi-environment testing**

## Quick Start

### Install Test Dependencies

```bash
# Install test requirements
pip install -r requirements-test.txt

# Or install everything including test dependencies
pip install -r requirements.txt -r requirements-test.txt
```

### Run All Tests

```bash
# Simple test run
pytest

# Run with coverage
pytest --cov=text_manipulation

# Run with detailed coverage report
python test_runner.py --coverage-html
```

## Test Structure

```
tests/
├── __init__.py
├── unit/                    # Unit tests
│   ├── core/               # Core functionality tests
│   │   ├── test_extractors.py
│   │   ├── test_config.py
│   │   └── api_clients/    # API client tests
│   │       └── test_virustotal.py
│   └── cli/                # CLI component tests
│       └── test_interface.py
├── integration/            # Integration tests
│   └── test_end_to_end.py
└── fixtures/               # Test data and fixtures
    └── test_data.py
```

## Test Categories

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.slow` - Slow-running tests
- `@pytest.mark.api` - API-related tests
- `@pytest.mark.cli` - CLI interface tests
- `@pytest.mark.core` - Core functionality tests

## Running Tests

### Using pytest directly

```bash
# Run all tests
pytest

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m api

# Run specific test files
pytest tests/unit/core/test_extractors.py

# Run tests matching a pattern
pytest -k "test_extract"

# Run with verbose output
pytest -v

# Run in parallel (requires pytest-xdist)
pytest -n 4
```

### Using the test runner script

```bash
# Run unit tests only
python test_runner.py --unit

# Run integration tests only
python test_runner.py --integration

# Run with coverage report
python test_runner.py --coverage

# Run with HTML coverage report
python test_runner.py --coverage-html

# Run code quality checks
python test_runner.py --lint
python test_runner.py --type-check
python test_runner.py --all-checks

# Run specific test file
python test_runner.py --file tests/unit/core/test_extractors.py

# Run tests matching pattern
python test_runner.py --pattern "extract"
```

### Using tox for multi-environment testing

```bash
# Run tests across all Python versions
tox

# Run tests for specific Python version
tox -e py39

# Run specific test environment
tox -e coverage
tox -e flake8
tox -e mypy
```

## Configuration Files

### pytest.ini
Main pytest configuration including:
- Test discovery settings
- Coverage configuration
- Report generation settings
- Marker definitions

### .coveragerc
Coverage measurement configuration:
- Source code inclusion/exclusion
- Report formatting
- Branch coverage settings

### tox.ini
Multi-environment testing configuration:
- Python version testing
- Code quality checks
- Coverage reporting

## Test Fixtures and Mocking

### Available Fixtures

The `conftest.py` file provides many useful fixtures:

```python
def test_example(sample_ips, mock_api_response, temp_dir):
    """Example test using fixtures."""
    # sample_ips: List of test IP addresses
    # mock_api_response: Mock API response data
    # temp_dir: Temporary directory for test files
    pass
```

### Common Fixtures

- `temp_dir` - Temporary directory for test files
- `sample_text_file` - Sample text file with test data
- `sample_ips` - List of test IP addresses
- `sample_urls` - List of test URLs
- `sample_hashes` - Dictionary of test hashes by type
- `mock_api_response` - Generic API response mock
- `mock_virustotal_response` - VirusTotal API response mock
- `mock_shodan_response` - Shodan API response mock
- `cli_instance` - CLI interface instance
- `test_config` - Test configuration object

### Mocking Examples

```python
# Mock API calls
@patch('text_manipulation.core.api_clients.virustotal.VirusTotalClient')
def test_api_integration(mock_client):
    mock_client.return_value.query_ip.return_value = {"data": {...}}
    # Test implementation

# Mock file operations
@patch("builtins.open", new_callable=mock_open, read_data="test content")
def test_file_processing(mock_file):
    # Test implementation

# Mock CLI input
@patch('builtins.input', side_effect=['1', 'test input', 'quit'])
def test_cli_interaction(mock_input):
    # Test implementation
```

## Coverage Reporting

### Generate Coverage Reports

```bash
# Terminal coverage report
pytest --cov=text_manipulation --cov-report=term-missing

# HTML coverage report
pytest --cov=text_manipulation --cov-report=html

# XML coverage report (for CI/CD)
pytest --cov=text_manipulation --cov-report=xml

# All formats
pytest --cov=text_manipulation --cov-report=html --cov-report=xml --cov-report=term
```

### Coverage Targets

- **Minimum coverage**: 80%
- **Exclude from coverage**: Test files, venv, __pycache__

### View HTML Coverage Report

```bash
# Generate HTML report
pytest --cov=text_manipulation --cov-report=html

# Open in browser (Linux/macOS)
open htmlcov/index.html

# Open in browser (Windows)
start htmlcov/index.html
```

## Performance Testing

Performance tests are marked with `@pytest.mark.slow`:

```bash
# Run performance tests
pytest -m slow

# Run performance tests with custom timeout
pytest -m slow --timeout=30
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.9, 3.10, 3.11, 3.12]
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    - name: Install dependencies
      run: |
        pip install -r requirements.txt -r requirements-test.txt
    - name: Run tests
      run: |
        pytest --cov=text_manipulation --cov-report=xml
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

## Writing New Tests

### Test Naming Convention

- Test files: `test_*.py` or `*_test.py`
- Test classes: `Test*`
- Test functions: `test_*`

### Example Unit Test

```python
"""
Unit tests for new functionality.
"""

import pytest
from unittest.mock import Mock, patch

from text_manipulation.core.new_module import NewClass


@pytest.mark.unit
@pytest.mark.core
class TestNewClass:
    """Test class for new functionality."""

    @pytest.fixture
    def instance(self):
        """Create an instance for testing."""
        return NewClass()

    def test_basic_functionality(self, instance):
        """Test basic functionality."""
        result = instance.do_something("input")
        assert result == "expected_output"

    @patch('text_manipulation.core.new_module.external_dependency')
    def test_with_mocking(self, mock_dependency, instance):
        """Test with external dependency mocked."""
        mock_dependency.return_value = "mocked_result"
        
        result = instance.method_using_dependency()
        
        assert result == "processed_mocked_result"
        mock_dependency.assert_called_once()
```

### Example Integration Test

```python
"""
Integration tests for component interactions.
"""

import pytest
from unittest.mock import patch

from text_manipulation.cli.interface import TextManipulationCLI
from text_manipulation.core.extractors import extract_ips


@pytest.mark.integration
class TestComponentIntegration:
    """Test component integration."""

    def test_cli_to_extractor_flow(self, sample_text_file):
        """Test CLI to extractor integration."""
        # Test that CLI can properly call extractors
        content = sample_text_file.read_text()
        ips = extract_ips(content)
        
        assert len(ips) > 0
        assert all(isinstance(ip, str) for ip in ips)
```

## Debugging Tests

### Run with Debug Output

```bash
# Run with print statements visible
pytest -s

# Run with verbose output
pytest -v

# Run single test with debugging
pytest -s -v tests/unit/core/test_extractors.py::TestExtractors::test_extract_ips_valid
```

### Using pdb

```python
def test_debug_example():
    """Test with debugging."""
    import pdb; pdb.set_trace()
    # Test implementation
```

## Test Data Management

### Sample Data Location

Test data is stored in `tests/fixtures/test_data.py`:

```python
from tests.fixtures.test_data import SAMPLE_IPS, SAMPLE_URLS, MIXED_CONTENT_SAMPLE
```

### Creating Test Files

```python
def test_with_temp_file(temp_dir):
    """Test using temporary file."""
    test_file = temp_dir / "test.txt"
    test_file.write_text("test content")
    
    # Use test_file in your test
    assert test_file.exists()
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure `PYTHONPATH` includes project root
2. **Missing Fixtures**: Check `conftest.py` imports
3. **Mock Issues**: Verify mock paths match actual imports
4. **Coverage Issues**: Check `.coveragerc` configuration

### Debug Commands

```bash
# Check pytest configuration
pytest --help

# List available fixtures
pytest --fixtures

# Show test collection
pytest --collect-only

# Run with maximum verbosity
pytest -vv

# Show local variables on failure
pytest -l
```

## Best Practices

1. **Test Organization**: Group related tests in classes
2. **Descriptive Names**: Use clear, descriptive test names
3. **Single Responsibility**: Each test should test one thing
4. **Independence**: Tests should not depend on each other
5. **Mocking**: Mock external dependencies appropriately
6. **Data**: Use fixtures for reusable test data
7. **Performance**: Mark slow tests appropriately
8. **Documentation**: Document complex test scenarios

## Maintenance

### Regular Tasks

1. **Update test dependencies** when main dependencies change
2. **Review coverage reports** to identify untested code
3. **Update mock data** when APIs change
4. **Performance baseline** updates for slow tests
5. **Test data cleanup** to remove obsolete fixtures

### Monitoring

- Monitor test execution time
- Track coverage trends
- Review test failure patterns
- Update test environments regularly 