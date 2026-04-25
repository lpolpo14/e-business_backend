
"""
Tests the CLI proper workings, specifically the inputs.
Exit Codes can be translated as such
0: All good, no error
1: Abort Exception
2: Help page is displayed due to incorrect user input

Class implementation in present test is not really necessary, but still a good way to learn!
"""

from click.testing import CliRunner
from d3fender.cli import cli 
import re
import pytest

class TestInputCLI:
    """
    Class contains tests for testing the various inputs the user may provide when first
    starting the app. Tests include parameter and options testing for the CLI.
    """

    VALID_FORMATS_JSON = ["json", "JSON", "JsOn"]
    INVALID_FORMATS_JSON = ["jon","JON", ""]
    VALID_FORMATS_TEXT = ["text", "TEXT", "TeXT"]
    INVALID_FORMATS_TEXT = [".txt", "txt"]

    VALID_FORMATS_HELP = ["--help", "-h"]

    def test_cli_starts(self):
        """Check if it runs with no parameters"""

        runner = CliRunner()
        result = runner.invoke(cli, ["assess"])
        assert result.exit_code == 2 # Output help page for commands

    @pytest.mark.parametrize("fmt_help", VALID_FORMATS_HELP)
    def test_cli_help(self, fmt_help):
        """ 
        Checks if --help/-h (as defined in fmt_help parameter) 
        options properly return the help page for the application
        """
        runner = CliRunner()
        result = runner.invoke(cli, ["assess", fmt_help])
        assert result.exit_code == 0
        assert "D3FENDer" in result.output
        assert "Options:" in result.output
        assert "--format " in result.output
        assert "--file" in result.output
        assert "--help" in result.output

    """ 
    @pytest.mark.parametrize("fmt_json",VALID_FORMATS_JSON)
    def test_cli_CorrectFormatInputJSON(self, fmt_json):
        
        Checks if when given proper JSON format (as defined in fmt_json)
        as a parameter that the app works properly.
        
        runner = CliRunner()
        result = runner.invoke(cli, ["assess", "--format",fmt_json])
        assert result.exit_code == 0

    @pytest.mark.parametrize("fmt_text",VALID_FORMATS_TEXT)
    def test_cli_CorrectFormatInputText(self, fmt_text):
        
        Checks if when given proper text format (as defined in fmt_text)
        as a parameter that the app works properly.
        
        runner = CliRunner()
        result = runner.invoke(cli, ["assess", "--format", fmt_text])
        assert result.exit_code == 0

    """
    @pytest.mark.parametrize("invalid_fmt_json",INVALID_FORMATS_JSON)
    def test_cli_FlawedFormatInputJSON(self, invalid_fmt_json):
        """
        Checks if when given the improper JSON format (as defined in invalid_fmt_json)
        as a parameter that the app does not work properly.
        """
        runner = CliRunner()
        result = runner.invoke(cli, ["assess", "--format", invalid_fmt_json])
        assert result.exit_code == 2

    @pytest.mark.parametrize("invalid_fmt_text", INVALID_FORMATS_TEXT)
    def test_cli_FlawedFormatInputText(self, invalid_fmt_text):
        """
        Checks if when given the improper text format (as defined in invalid_fmt_text)
        as a parameter that the app does not work properly.
        """
        runner = CliRunner()
        result = runner.invoke(cli, ["assess", "--format", invalid_fmt_text])
        assert result.exit_code == 2


    def test_cli_InvalidFileName(self, tmp_path):
        """
        Checks if when given an invalid file to read input from (existing defenses)
        the app does not continue and instead stops execution due to invalid user input.

        Args:
            tmp_path:   tmp_path is a global pytest variable that gives us a temporary
            path for us to conduct our testing.
        """

        invalid_file = tmp_path / "invalidFile.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["assess", "--file", invalid_file])
        assert result.exit_code == 2 


class TestVersionCLI:
    
    """
    This class includes tests which focus on the version of the application which is shown
    to the user when running the --version option.
    """

    def test_cli_version_works(self):
        """ Checks if the --version option works properly and displays the app's currenet version."""

        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output

    def test_cli_version_is_correct(self, pytestconfig):
        """
        Checks whether the version that the app displays matches the version poetry's pyproject.toml file has.
        
        Args:
             pytestconfig:   configuration for pytest used to get the
             root path so we can replicate tests.
        """
        import tomllib
        import pathlib

        project_root = pathlib.Path(pytestconfig.rootpath)
        pyproject_file_path = project_root / "pyproject.toml"
        with open(pyproject_file_path, "rb") as f: 
            data = tomllib.load(f)
        version = data["project"]["version"]

        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert version in result.output
