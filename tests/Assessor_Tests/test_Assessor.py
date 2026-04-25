"""
This module contains test for the application's assessor (Rule Based System)
The assessor is tested as a whole, without giving much examination to its sub-modules,
since the latter are checked diligently in separate tests.
"""

from d3fender.assessors.mainAssessor import runAssessment
from d3fender.IO.Output import render_findings

import pathlib

def testAssessor(pytestconfig):
    """
    Tests the main assessor using mock data.
    """
    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "tests/mockData/inputMockData.json"
    results = runAssessment("json",mockDataPath.read_text())
    assert len(results) == 13

def testAssessorWithOutput_JSON(pytestconfig):
    """
    Tests the main assessor using mock data with formatted output.
    """

    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "tests/mockData/inputMockData.json"
    results = runAssessment("json", mockDataPath.read_text())
    findings = render_findings(results)

    tokenBindingFlag = False
    for finding in findings:
        if "Missing Token Binding" in finding:
            tokenBindingFlag = True
    assert tokenBindingFlag == False # Fix this later.

def testAssessorWithOutput_TEXT(pytestconfig):
    userInput = ("We have token based authentication."
                 " We do not have token binding. We also have code scanning. We are a software engineering company.")
    findings = runAssessment("text", userInput)
    findings = render_findings(findings)

    tokenBindingFlag = False
    stackOverflowFlag = False
    for finding in findings:
        if "Missing Token Binding" in finding:
            tokenBindingFlag = True
        if "Missing Stack Overflow Mitigations" in finding:
            stackOverflowFlag = True
    assert tokenBindingFlag == True
    assert stackOverflowFlag == True