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
        click.secho("Technique was not found.", fg="red", bold=True)
        return

    click.echo(
        click.style("ID of D3FEND Technique:", fg="white", bold=True)
        + f" {technique.defend_id}"
    )

    click.echo(
        click.style("Technique name:", fg="white", bold=True)
        + f" {technique.name}"
    )

    click.echo(
        click.style("Technique definition:", fg="white", bold=True)
        + f" {technique.definition}"
    )

    click.echo(
        click.style("The goal of the specific technique is to", fg="white", bold=True)
        + f" {technique.tactic[4:]}"
    )

def printATTACKTechniqueToOutput(technique : AttackTechnique) -> None:
    """
    Prints the contents of the D3FEND Technique to the user using Click API.
    Args:
        technique: a DefendTechnique Object
    """
    if technique is None:
        click.secho("Technique was not found.", fg="red", bold=True)
        return

    click.echo(
        click.style("ID of ATT&CK Technique:", fg="white", bold=True)
        + f" {technique.external_id}"
    )

    click.echo(
        click.style("Technique name:", fg="white", bold=True)
        + f" {technique.name}"
    )

    click.echo(
        click.style("Technique description:", fg="white", bold=True)
        + f" {technique.description}"
    )

    click.echo(
        click.style("This technique supports the Tactics:", fg="white", bold=True)
        + f" {technique.tactics}"
    )

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

def list_to_concatenated_string(input_list : list) -> str:
    """
    Outputs a concatenated string from a list of elements, typically ATT&CK/D3FEND Techniques
    Every entry is concatenated using a comma (?)
    """
    output = ''
    for element in input_list:
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

def style_severity(severity: str) -> str:
    """
    Based on the severity score apply according color
    Args:
        severity: The severity score of a detected gap (low,medium,high)

    Returns:
        A coloured string (click.style)
    """
    severity_lower = severity.lower()
    if severity_lower == "low":
        return click.style("Low", fg="green", bold=True)
    elif severity_lower == "medium":
        return click.style("Medium", fg="yellow", bold=True)
    else:
        return click.style("High", fg="red", bold=True)

def render_finding(finding : Finding) -> str:
    """
        Renders a Single Finding object into a printable string.
    Args:
        finding: The Finding Object which contains structured information.

    Returns:
        A printable string representing the finding.
    """

    lines = []

    lines.append(
        click.style("Detected Security Gap:", fg="white", bold=True)
        + " "
        + click.style(finding.title, bold=True)
    )

    lines.append(
        click.style("Rule ID:", bold=True)
        + " "
        + f"{finding.rule_id}"
    )

    lines.append(
        click.style("Severity:", bold=True)
        + " "
        + style_severity(finding.severity)
    )

    lines.append(
        click.style("Description:", bold=True)
        + f" {finding.description}"
    )

    lines.append("")

    if finding.evidence:
        lines.append(click.style("Evidence:", fg="cyan", bold=True))
        lines.extend(render_evidence(finding.evidence))
        lines.append("")

    lines.append(
        click.style("Missing Capabilities:", fg="yellow", bold=True)
        + " "
        + list_to_concatenated_string(finding.missing_capabilities)
    )

    lines.append(
        click.style("ATT&CK Techniques:", fg="magenta", bold=True)
        + " "
        + list_to_concatenated_string(finding.attack_techniques)
    )

    lines.append(
        click.style("D3FEND Techniques:", fg="green", bold=True)
        + " "
        + list_to_concatenated_string(finding.d3fend_techniques)
    )

    lines.append("")
    lines.append(
        click.style("Recommendation:", fg="cyan", bold=True)
        + f" {finding.recommendation}"
    )

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