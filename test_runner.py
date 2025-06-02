#!/usr/bin/env python3
"""
Test runner script for the text manipulation tool.

This script provides various options for running tests including:
- Unit tests only
- Integration tests only
- All tests
- Coverage reports
- Specific test categories

Usage:
    python test_runner.py [options]
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path


def run_command(command, description=""):
    """Run a command and return the result."""
    print(f"\n{'='*60}")
    print(f"Running: {description or command}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(command, shell=True, check=True)
        print(f"\n✅ SUCCESS: {description or command}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ FAILED: {description or command}")
        print(f"Exit code: {e.returncode}")
        return False


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description="Test runner for text manipulation tool")
    
    # Test type options
    parser.add_argument('--unit', action='store_true', 
                       help='Run unit tests only')
    parser.add_argument('--integration', action='store_true',
                       help='Run integration tests only')
    parser.add_argument('--slow', action='store_true',
                       help='Run slow tests only')
    parser.add_argument('--api', action='store_true',
                       help='Run API tests only')
    parser.add_argument('--cli', action='store_true',
                       help='Run CLI tests only')
    parser.add_argument('--core', action='store_true',
                       help='Run core functionality tests only')
    
    # Coverage options
    parser.add_argument('--coverage', action='store_true',
                       help='Run tests with coverage report')
    parser.add_argument('--coverage-html', action='store_true',
                       help='Generate HTML coverage report')
    
    # Code quality options
    parser.add_argument('--lint', action='store_true',
                       help='Run code linting (flake8)')
    parser.add_argument('--type-check', action='store_true',
                       help='Run type checking (mypy)')
    parser.add_argument('--all-checks', action='store_true',
                       help='Run all code quality checks')
    
    # Output options
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Quiet output')
    parser.add_argument('--parallel', '-n', type=int,
                       help='Number of parallel workers')
    
    # Test selection
    parser.add_argument('--file', type=str,
                       help='Run specific test file')
    parser.add_argument('--pattern', type=str,
                       help='Run tests matching pattern')
    
    args = parser.parse_args()
    
    # Set up base directory
    base_dir = Path(__file__).parent
    os.chdir(base_dir)
    
    # Build pytest command
    pytest_cmd = "pytest"
    
    # Add verbosity options
    if args.verbose:
        pytest_cmd += " -v"
    elif args.quiet:
        pytest_cmd += " -q"
    
    # Add parallel execution
    if args.parallel:
        pytest_cmd += f" -n {args.parallel}"
    
    # Add specific file or pattern
    if args.file:
        pytest_cmd += f" {args.file}"
    elif args.pattern:
        pytest_cmd += f" -k {args.pattern}"
    
    # Track success/failure
    all_passed = True
    
    # Run specific test categories
    if args.unit:
        cmd = f"{pytest_cmd} -m unit"
        all_passed &= run_command(cmd, "Unit Tests")
        
    elif args.integration:
        cmd = f"{pytest_cmd} -m integration"
        all_passed &= run_command(cmd, "Integration Tests")
        
    elif args.slow:
        cmd = f"{pytest_cmd} -m slow"
        all_passed &= run_command(cmd, "Slow Tests")
        
    elif args.api:
        cmd = f"{pytest_cmd} -m api"
        all_passed &= run_command(cmd, "API Tests")
        
    elif args.cli:
        cmd = f"{pytest_cmd} -m cli"
        all_passed &= run_command(cmd, "CLI Tests")
        
    elif args.core:
        cmd = f"{pytest_cmd} -m core"
        all_passed &= run_command(cmd, "Core Tests")
        
    elif args.coverage or args.coverage_html:
        # Run with coverage
        cmd = f"{pytest_cmd} --cov=text_manipulation --cov-report=term-missing"
        if args.coverage_html:
            cmd += " --cov-report=html:htmlcov --cov-report=xml:coverage.xml"
        all_passed &= run_command(cmd, "Tests with Coverage")
        
        if args.coverage_html:
            print("\n📊 HTML coverage report generated in 'htmlcov' directory")
    
    else:
        # Run all tests by default
        all_passed &= run_command(pytest_cmd, "All Tests")
    
    # Run code quality checks
    if args.lint or args.all_checks:
        flake8_cmd = "flake8 text_manipulation tests"
        all_passed &= run_command(flake8_cmd, "Code Linting (flake8)")
    
    if args.type_check or args.all_checks:
        mypy_cmd = "mypy text_manipulation"
        all_passed &= run_command(mypy_cmd, "Type Checking (mypy)")
    
    # Final summary
    print(f"\n{'='*60}")
    if all_passed:
        print("🎉 ALL CHECKS PASSED!")
        print("Your code is ready for deployment.")
    else:
        print("❌ SOME CHECKS FAILED")
        print("Please review the output above and fix any issues.")
    print(f"{'='*60}\n")
    
    # Exit with appropriate code
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main() 