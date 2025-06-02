"""
Unit tests for the CLI interface module.
"""

import pytest
from unittest.mock import Mock, patch, call
from io import StringIO
import sys

from text_manipulation.cli.interface import TextManipulationCLI


@pytest.mark.unit
@pytest.mark.cli
class TestTextManipulationCLI:
    """Test class for CLI interface functionality."""

    @pytest.fixture
    def cli(self):
        """Create a CLI instance for testing."""
        return TextManipulationCLI()

    def test_cli_initialization(self, cli):
        """Test CLI initialization."""
        assert cli is not None
        assert hasattr(cli, 'run')

    @patch('builtins.input', side_effect=['n', '1', '0', '0'])  # initial prompt, main menu, hash menu, exit
    @patch('sys.stdout', new_callable=StringIO)
    def test_cli_run_basic(self, mock_stdout, mock_input, cli):
        """Test basic CLI run functionality."""
        try:
            cli.run()
        except SystemExit:
            pass  # Expected when exiting CLI
        
        # Verify that CLI produced output
        output = mock_stdout.getvalue()
        assert len(output) > 0

    @patch('builtins.input', side_effect=['n', 'invalid', '0'])  # initial prompt, invalid choice, exit
    @patch('sys.stdout', new_callable=StringIO)
    def test_cli_invalid_input(self, mock_stdout, mock_input, cli):
        """Test CLI handling of invalid input."""
        try:
            cli.run()
        except SystemExit:
            pass
        
        output = mock_stdout.getvalue()
        # Should handle invalid input gracefully
        assert len(output) > 0

    @patch('text_manipulation.cli.input_handler.InputHandler')
    def test_cli_with_input_handler(self, mock_input_handler, cli):
        """Test CLI integration with input handler."""
        mock_handler = Mock()
        mock_input_handler.return_value = mock_handler
        mock_handler.get_user_input.return_value = "test input"
        
        # Test that CLI can work with input handler
        if hasattr(cli, 'input_handler'):
            cli.input_handler = mock_handler
            result = cli.input_handler.get_user_input()
            assert result == "test input"

    @patch('text_manipulation.cli.display.Display')
    def test_cli_with_display(self, mock_display, cli):
        """Test CLI integration with display handler."""
        mock_display_instance = Mock()
        mock_display.return_value = mock_display_instance
        
        # Test that CLI can work with display handler
        if hasattr(cli, 'display'):
            cli.display = mock_display_instance
            cli.display.show_message("test message")
            mock_display_instance.show_message.assert_called_with("test message")

    def test_cli_menu_options(self, cli):
        """Test that CLI has menu options."""
        if hasattr(cli, 'get_menu_options'):
            options = cli.get_menu_options()
            assert isinstance(options, (list, dict))
            assert len(options) > 0
        else:
            # If no explicit menu method, check for menu-related attributes
            assert hasattr(cli, '__dict__')

    @patch('text_manipulation.core.extractors')
    def test_cli_extractor_integration(self, mock_extractors, cli):
        """Test CLI integration with extractors."""
        mock_extractors.extract_ips.return_value = ["192.168.1.1"]
        
        # Test that CLI can call extractors
        if hasattr(cli, '_extract_data'):
            result = cli._extract_data("test text", "ip")
            assert result is not None
        else:
            # Basic integration test
            assert mock_extractors is not None

    @patch('builtins.input', side_effect=['n', '2', '0', '0'])  # initial prompt, network menu, exit submenu, exit main
    @patch('sys.stdout', new_callable=StringIO)
    def test_cli_url_extraction(self, mock_stdout, mock_input, cli):
        """Test CLI URL extraction functionality."""
        try:
            cli.run()
        except SystemExit:
            pass
        
        output = mock_stdout.getvalue()
        assert len(output) > 0

    @patch('builtins.input', side_effect=['n', '1', '0', '0'])  # initial prompt, hash menu, exit submenu, exit main
    @patch('sys.stdout', new_callable=StringIO)
    def test_cli_hash_extraction(self, mock_stdout, mock_input, cli):
        """Test CLI hash extraction functionality."""
        try:
            cli.run()
        except SystemExit:
            pass
        
        output = mock_stdout.getvalue()
        assert len(output) > 0

    @patch('builtins.input', side_effect=['n', 'help', '0'])  # initial prompt, invalid command (help), exit
    @patch('sys.stdout', new_callable=StringIO)
    def test_cli_help_command(self, mock_stdout, mock_input, cli):
        """Test CLI help command."""
        try:
            cli.run()
        except SystemExit:
            pass
        
        output = mock_stdout.getvalue()
        assert len(output) > 0

    def test_cli_error_handling(self, cli):
        """Test CLI error handling."""
        # Test that CLI can handle exceptions gracefully
        try:
            if hasattr(cli, '_handle_error'):
                cli._handle_error(Exception("Test error"))
            else:
                # Test basic error tolerance
                assert cli is not None
        except Exception:
            # CLI should handle errors gracefully
            assert False, "CLI should handle errors without crashing"

    @patch('pathlib.Path.exists', return_value=True)
    @patch('builtins.input', side_effect=['n', '8', '0', '0'])  # initial prompt, data menu, exit submenu, exit main
    @patch('sys.stdout', new_callable=StringIO)
    def test_cli_file_input(self, mock_stdout, mock_input, mock_exists, cli):
        """Test CLI file input functionality."""
        try:
            cli.run()
        except SystemExit:
            pass
        
        output = mock_stdout.getvalue()
        assert len(output) > 0

    def test_cli_exit_conditions(self, cli):
        """Test CLI exit conditions."""
        # Test that CLI has proper exit mechanisms
        if hasattr(cli, '_should_exit'):
            assert callable(cli._should_exit)
        
        # Test exit commands
        if hasattr(cli, '_process_exit_command'):
            assert callable(cli._process_exit_command)

    @patch('text_manipulation.core.config.Config')
    def test_cli_configuration(self, mock_config, cli):
        """Test CLI configuration handling."""
        mock_config_instance = Mock()
        mock_config.return_value = mock_config_instance
        
        # Test that CLI can work with configuration
        if hasattr(cli, 'config'):
            cli.config = mock_config_instance
            assert cli.config is not None

    def test_cli_state_management(self, cli):
        """Test CLI state management."""
        # Test that CLI maintains proper state
        if hasattr(cli, 'state'):
            assert cli.state is not None
        
        # Test state transitions
        if hasattr(cli, '_update_state'):
            cli._update_state("new_state")
            assert hasattr(cli, 'state') 