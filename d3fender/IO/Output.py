"""
This module focuses enhancing the results' presentability through proper parsing and formatting.
The results produced by this module can be shown to the user as is without further manipulation.
"""
from dataclasses import asdict, is_dataclass

import click

from d3fender.models.attackModels import AttackTechnique
from d3fender.models.defendModels import DefendTechnique
from d3fender.rules.Finding import Finding


def printD3FENDTechniqueToOutput(technique : DefendTechnique) -> None:
    """
    Prints the contents of the D3FEND Technique to the user using Click API.
    Args:
        technique: a DefendTechnique Object
    """
    if technique is None:
        click.echo(f"Technique was not found.")
        return
    click.echo(f"ID of D3FEND Technique: {technique.defend_id}")
    click.echo(f"Technique name: {technique.name}")
    click.echo(f"Technique definition: {technique.definition}")
    click.echo(f"The goal of the specific technique is to {technique.tactic[4:]}" )

def printATTACKTechniqueToOutput(technique : AttackTechnique) -> None:
    """
    Prints the contents of the D3FEND Technique to the user using Click API.
    Args:
        technique: a DefendTechnique Object
    """
    if technique is None:
        click.echo(f"Technique was not found.")
        return
    click.echo(f"ID of ATT&CK Technique: {technique.external_id}")
    click.echo(f"Technique name: {technique.name}")
    click.echo(f"Technique description: {technique.description}")
    click.echo(f"This technique supports the Tactics '{technique.tactics}'" )

def RulesToListDictionaries(rules : list) -> list:
    """
    DEPRECATED!

    Transforms a list containing rule objects into a list of dictionaries.
    Each dictionary represents a rule object that can be outputted to the user.
    Args:
        rules (list): A list of rule objects
    Returns:
        list: A list of dictionaries representing the rule objects
    """
    listOfRules = []
    for rule in rules:
        currentRule = {}
        currentRule['rule'] = rule.getDescription()
        currentRule['missingCapability'] = rule.getMissingCapability()
        currentRule['attackTechniques'] = list_to_concatenated_string(rule.getAttackTechniques())
        currentRule['d3fendTechniques'] = list_to_concatenated_string(rule.getD3fendTechniques())
        listOfRules.append(currentRule)
    return listOfRules

def list_to_concatenated_string(input : list) -> str:
    """
    Outputs a concatenated string from a list of elements, typically ATT&CK/D3FEND Techniques
    Every entry is concatenated using a comma (?)
    """
    output = ''
    for element in input:
        output += str(element)
        output += ', '
    return output[:-2]

def finding_as_dict(finding : Finding) -> dict:
    """
    Transforms a finding object into a dictionary.
    Args:
        finding: A Finding Object

    Returns:
        A Dictionary representing the finding object.
    """
    if is_dataclass(finding):
        return asdict(finding)

    # Just in case.
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "recommendation": finding.recommendation,
        "missing_capabilities": finding.missing_capabilities,
        "attack_techniques": finding.attack_techniques,
        "d3fend_techniques": finding.d3fend_techniques,
        "evidence": finding.evidence,
    }

def render_finding(finding : Finding) -> str:
    """
        Renders a Single Finding object into a printable string.
    Args:
        finding: The Finding Object which contains structured information.

    Returns:
        A printable string representing the finding.
    """

    lines = [
        f"Detected Security Gap: {finding.title}",
        f"Rule ID: {finding.rule_id}",
        f"Severity: {finding.severity}",
        f"Description: {finding.description}",
        "",
    ]

    if finding.evidence:
        lines.append("Evidence:")
        lines.extend(render_evidence(finding.evidence))
        lines.append("")

    lines.append(
        f"Missing Capabilities: {list_to_concatenated_string(finding.missing_capabilities)}"
    )
    lines.append(
        f"Correlated ATT&CK Techniques: {list_to_concatenated_string(finding.attack_techniques)}"
    )
    lines.append(
        f"Suggested D3FEND Techniques: {list_to_concatenated_string(finding.d3fend_techniques)}"
    )
    lines.append("")
    lines.append(f"Recommendation: {finding.recommendation}")

    return "\n".join(lines)


def render_findings(findings : list) -> list[str]:
    """
    Renders a list of Finding objects. Can be printed as output to user.
    Args:
        findings: A list containing finding objects

    Returns:
        A printable string representing the findings.
    """
    return [render_finding(finding) for finding in findings]

def render_evidence(evidence: dict) -> list[str]:
    """
    Renders an Evidence object into a printable string.
    Args:
        evidence: The evidence dict containing information about relevant capabilities.
    Returns:
        A printable string representing the evidence.
    """
    lines = []
    for key, value in evidence.items():
        lines.append(f"  - {key}: {value}")
    return lines