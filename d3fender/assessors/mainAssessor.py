"""
This module assesses an organization's defensive status based on the provided input.
The assessor works only with parsed and specific input that is created by other modules.
The assessor is the main implementation of the described Rule Based System.
"""
from d3fender.IO.Input import interactive_input
from d3fender.input.registry_loader import load_capability_registry, load_controls_registry
from d3fender.rules.baseRules import getAllRules as getRules
from d3fender.rules.ruleEvaluator import evaluateRules as evaluate

from d3fender.input.inputParser import (retrieveInputJsonDataFromString as inputJson,
                                        normalize_json_input_to_capabilities as normalizeJsonInput,
                                        normalize_plaintext_input_to_capabilities as normalizePlaintextInput)

def runAssessment(input_format: str, content: str) -> list:
    """
    The main assessment method. Handles the entire logic of the assessment and of the application
    in a sequential logic.
    Args:
        fileFormat: The file's format - JSON or .txt .
        content: The content of the file given as input that contains the details of the organization's defensive structure
    Returns:
        A list containing objects of the Findings.
    """

    capabilities_registry = load_capability_registry()
    controls_registry = load_controls_registry()
    canonical = get_canonical_input(input_format, content, capabilities_registry, controls_registry)

    activeRules = getRules()
    results = evaluate(canonical, activeRules)
    
    return results


def get_canonical_input(input_format: str,
                        content: str,
                        capabilities_registry: dict,
                        controls_registry: dict) -> dict:
    """
        Returns the canonical input containing the setup capabilities from the registry.
    Args:
        fileFormat: the file's format - 'json' or 'text'.
        content: The content of the file or text
        registry: The registry containing the capabilities.

    Returns:

    """

    if input_format == "json":
        fileJSON = inputJson(content)
        return normalizeJsonInput(fileJSON, capabilities_registry, controls_registry)

    if input_format == "text":
        from d3fender.NLP.SentenceTransformer import DefensesSentenceTransformer

        sentenceTransformer = DefensesSentenceTransformer(capabilities_registry, controls_registry)
        return normalizePlaintextInput(content, capabilities_registry, controls_registry, sentenceTransformer)

    if input_format == "interactive":
        return interactive_input(capabilities_registry, controls_registry)

    raise ValueError(f"Unsupported file format: {input_format}")
