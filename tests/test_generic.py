"""
This file handles generic tests for the d3fender application, mainly in context
to how it relates to the git repository, poetry dependency manager, and generally
to the development process. I do not plan on testing code written by me here, just generic tests.
"""

# tests/test_basic.py
import d3fender

def test_import_package():
    """
    Assert that the __init__ file for d3fender's main package has a version attribute.
    """
    assert hasattr(d3fender, "__version__")

def test_project_version_match_pyproject(pytestconfig):
    """
    Make sure that pyproject.toml version matches the defender's main package version attribute.

    Args:
        pytestconfig:   configuration for pytest used to get the root path so we can replicate tests
        in various environments.
    """
    import tomllib
    import pathlib

    project_root = pathlib.Path(pytestconfig.rootpath)
    pyproject_file_path = project_root / "pyproject.toml"
    with open(pyproject_file_path, "rb") as f: 
        data = tomllib.load(f)
    version = data["project"]["version"]
    assert d3fender.__version__ == version 
    
