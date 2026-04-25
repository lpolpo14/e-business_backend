"""
Tests the proper working of the capabilities.json file
"""

import pytest
import pathlib
import d3fender.input.inputParser as iP
import d3fender.NLP.SentenceTransformer as sT


def test_json_input_normalizer_capabilities(pytestconfig):
    """
    Tests the method normalize_json_input_to_capabilities to see if capabilities are properly normalized
    Args:
        pytestconfig: configuration parameter used for retrieving
        root path in order to replicate future tests.

    """
    project_root = pathlib.Path(pytestconfig.rootpath)
    mockCapabilitiesDataPath = project_root / "tests/mockData/capabilities_MOCK.json"
    mockDataPath = project_root / "tests/mockData/inputMockData.json"
    mockControlsDataPath = project_root / "tests/mockData/mock_controls.json"

    mockData = iP.retrieveInputJsonDataFromFile(mockDataPath)

    mockCapabilitiesData = iP.retrieve_registry_data_from_file(mockCapabilitiesDataPath)
    mockControlsData = iP.retrieve_registry_data_from_file(mockControlsDataPath)
    canonical = iP.normalize_json_input_to_capabilities(mockData,mockCapabilitiesData, mockControlsData)

    capabilities = canonical["capabilities"]
    assert (capabilities["cred.token_binding"] is False)
    #assert (capabilities["auth.token_based_authentication"] is True)

    #context = canonical["threat_context"]
    #assert context.get("involves_software_engineering", False) == True

    #assert False
    ### Add Control tests.

def test_text_input_normalizer(pytestconfig):
    """
        Tests the method normalize_plaintext_input_to_capabilities to see if capabilities are properly normalized
        Args:
            pytestconfig: configuration parameter used for retrieving
            root path in order to replicate future tests.
    """
    project_root = pathlib.Path(pytestconfig.rootpath)
    mockCapabilitiesDataPath = project_root / "tests/mockData/capabilities_MOCK.json"
    mockCapabilitiesData = iP.retrieve_registry_data_from_file(mockCapabilitiesDataPath)
    mockControlsDataPath = project_root / "tests/mockData/mock_controls.json"
    mockControlsData = iP.retrieve_registry_data_from_file(mockControlsDataPath)

    sentenceTransformer = sT.DefensesSentenceTransformer(mockCapabilitiesData, mockControlsData)

    mockTextInput = ("We have token based authentication. We do not have token binding.\n"
                     "We also have code scanning")

    canonical = iP.normalize_plaintext_input_to_capabilities(mockTextInput,
                                                             mockCapabilitiesData,
                                                             mockControlsData,
                                                             sentenceTransformer)

    capabilities = canonical["capabilities"]
    assert len(capabilities) == 9
    assert (capabilities["cred.token_binding"] is False)
    assert (capabilities["auth.token_based_authentication"] is True)
    assert (capabilities["sw.code_analysis"] is True)

    # assert False Fix Later
    ### Add Control tests.