"""
This module is responsible for testing
"""

import d3fender.NLP.SentenceTransformer as sT
import pathlib
import d3fender.input.inputParser as iP


def test_sentence_transformer_embeddings(pytestconfig):
    """
    Tests the proper working of the SentenceTransformer Initialization
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
    assert sentenceTransformer.embeddings.shape == (15,384) # Number of Capabilities + Controls times 384.

