"""
This module is responsible for communicating with the OSV (Open Source Vulnerabilities) API
in order to detect vulnerabilities for SBOM.
"""

import requests

from d3fender.sbom_analysis.sbom_models import SBOMComponent, SBOMVulnerability

OSV_URL = "https://api.osv.dev/v1/query"

def query_OSV_for_component(component:SBOMComponent) -> list[SBOMVulnerability]:
    """
    Queries the OSV database to search for vulnerabilities for a specific component.
    Args:
        component: The component to query.
    Returns:
        A list of SBOM Vulnerabilities objects.
    """
    pURL = component.purl
    if not pURL:
        return [] # Fix this in the future to use name/version
        # as well (If needed of course, may be a bit overkill)

    payload = {
        "package": {"purl": pURL}
    }

    #if component.version: # This might cause errors. Remove it.
    #    payload["version"] = component.version

    r = requests.post(OSV_URL, json=payload)
    r.raise_for_status()

    vulns = r.json().get("vulns", [])

    return [parse_OSV_vulnerability(component,vuln) for vuln in vulns]

def parse_OSV_vulnerability(component:SBOMComponent, vuln: dict) -> SBOMVulnerability:
    """
    Parses a dict object containing OSV vulnerabilities into a SBOM Vulnerability object.
    Args:
        component: The component for which the vulnerability was found
        vuln: A vulnerability dict
    Returns:
        A structured SBOMVulnerability object.
    """
    return SBOMVulnerability(
        component=component,
        vulnerability_id=vuln.get("id", "UNKNOWN"),
        aliases=vuln.get("aliases", []),
        severity=format_OSV_severity(vuln.get("severity", {})),
        summary=vuln.get("summary", ""),
        details=vuln.get("details", ""),
        references=vuln.get("references", []),
    )

def format_OSV_severity(severities:dict) -> str:
    """
    Formats a severity string without using dicts.
    Args:
        severities: A dict object containing severities.
    Returns:
        A string with formatted severities.
    """
    if not severities:
        return ""

    if isinstance(severities, str):
        return severities

    formatted = []
    for severity in severities:
        if isinstance(severity, dict):
            formatted.append(f"{severity.get("type", "Score")}: {severity.get("score")}")
        else:
            formatted.append(str(severity))

    return "\n".join(formatted)