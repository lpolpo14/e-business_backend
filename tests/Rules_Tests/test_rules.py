"""
Handles generic tests for the proper working of specific rules in correlation with the rule based system.
"""

from d3fender.rules import baseRules as R
from d3fender.rules import ruleEvaluator as evaluator
import d3fender.input.inputParser as iP
import pathlib

def testRulesWithoutEvaluator():
    """
    Tests single hardcoded rule without the rule evaluation system.
    """

    assert R.TokenBindingRULE.applies({"auth.token_based_authentication":True, "cred.token_binding":False}) is True

def testCurrentRules():
    """
    Tests whether all rules are returned properly
    """
    rules = R.getAllRules()
    assert len(rules) == 20

"""
Deprecated
def testRuleEvaluatorWithFile(pytestconfig):
    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "tests/mockData/inputMockData.json"
    mockData = iP.retrieveInputJsonDataFromFile(mockDataPath)
    parsedData = iP.parseInputJsonDataFile_onlyLeaves(mockData)

    results = evaluator.evaluateRules(parsedData,R.getAllRules())
    assert len(results) == 2
    assert results[0].getRuleID() == "AUTH_1-TOKEN_BINDING"
"""

def test_Rule_Evaluator_With_File(pytestconfig):
    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "tests/mockData/inputMockData.json"
    mockData = iP.retrieveInputJsonDataFromFile(mockDataPath)
    from d3fender.input.registry_loader import load_capability_registry, load_controls_registry
    parsedData = iP.normalize_json_input_to_capabilities(mockData, load_capability_registry(), load_controls_registry())


    results = evaluator.evaluateRules(parsedData, R.getAllRules())
    assert len(results) == 13 ### Verify Later
