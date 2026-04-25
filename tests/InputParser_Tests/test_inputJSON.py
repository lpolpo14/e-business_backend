"""
This test collection checks and verifies the proper workings of the JSON input parser.
"""

import pytest
import json
import pathlib
import d3fender.input.inputParser as iP

def test_ParseMockInputData_leaves(pytestconfig):
    """
    Uses the parser to check a single hardcoded json mock file.
    Note: This tests only the leaf function.
    Args:
        pytestconfig: configuration parameter used for retrieving
        root path in order to replicate future tests.
    """

    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "tests/mockData/inputMockData.json"
    mockData = iP.retrieveInputJsonDataFromFile(mockDataPath)
    parsedData = iP.parseInputJsonDataFile_onlyLeaves(mockData)
    assert parsedData["certificate_pinning"] is False and parsedData["assessor"] == "Michael"
    assert parsedData.get("metadata", "empty") == "empty"

    
def test_ParseMockInputData_fullpath(pytestconfig):
    """
    Uses the parser to check a single hardcoded json mock file.
    Args:
        pytestconfig: configuration parameter used for retrieving
        root path in order to replicate future tests.
    """
    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "tests/mockData/inputMockData.json"
    mockData = iP.retrieveInputJsonDataFromFile(mockDataPath)
    flattenedData = iP.flatten_json_paths(mockData)
    assert (flattenedData["defensive_controls.credential_hardening.certificate_pinning"] is False
            and flattenedData["metadata.assessor"] == "Michael")