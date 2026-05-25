"""
This module is responsible for printing SBOM related findings.
"""
from dataclasses import is_dataclass, asdict

import click

from d3fender.sbom_analysis.sbom_models import SBOMComponent, SBOMVulnerability


def print_rendered_components(rendered_components):
    """
    Prints the rendered components using Click.
    """
    click.secho("SBOM Components:", fg="cyan")
    for rendered_component in rendered_components:
        click.echo(rendered_component)
        click.echo("-"*60)


def render_components(components) -> list[str]:
    """
    Renders the sbom components details
    Args:
        components: The components to print
    Returns:
        A list containing rendered components (printable to user as is)
    """
    return [render_component(component) for component in components]


def render_component(component: SBOMComponent) -> str:
    """
    Renders a single sbom component
    Args:
        component: The sbom component to be rendered
    """
    lines = []

    if component.name:
        lines.append(click.style("Component's name:", fg="white", bold=True)
        + " "
        + f"{component.name}")

    if component.version:
        lines.append(click.style("Component's version", fg="white", bold=True)
                     + " "
                     + f"{component.version}")


    if not component.name and not component.version:
        lines.append(click.style("Bom-Ref", fg="white", bold=True)
                    + " "
                    + f"{component.bom_ref}"
                 )

    return "\n".join(lines)


def component_as_dict(component):
    if is_dataclass(component):
        return asdict(component)

    if hasattr(component, "__dict__"):
        return component.__dict__

    return str(component)

def render_vulnerabilities(vulnerabilities:dict[str,list[SBOMVulnerability]]) -> str:
    """
    Responsible for formating the vulnerabilities for each component.
    Args:
        vulnerabilities: The dict containing the vulnerabilities for various components.
    Returns:
        A list of strings, where each string represents vulnerabilities for a specific component.
    """
    lines = []
    for bom_ref, component_vulnerabilities in vulnerabilities.items():
        if not component_vulnerabilities:
            continue

        component = component_vulnerabilities[0].component

        if component.name:
            lines.append(click.style("Vulnerable Component's name:", fg="white", bold=True)
            + " "
            + f"{component.name}")
        else:
            lines.append(click.style("Vulnerable Component's Bom-Ref:", fg="white", bold=True)
            + " "
            + f"{component.bom_ref}")

        if component.version:
            lines.append(click.style("Vulnerable Component's Version:", fg="white", bold=True)
            + " "
            + f"{component.version}")

        vulnerabilities_count = len(component_vulnerabilities)
        temp_text = " Vulnerabilities Detected"  if vulnerabilities_count > 1 else " Vulnerability Detected"
        vuln_text = str(vulnerabilities_count) + temp_text

        lines.append(click.style(vuln_text, fg="red", bold=True))

        for vulnerability in component_vulnerabilities:
            lines.append(" ")
            lines.append(click.style("Vulnerability's ID:", fg="white", bold=True)
                         + " "
                         + f"{vulnerability.vulnerability_id}")

            if vulnerability.aliases:
                lines.append(click.style("Aliases:", fg="white", bold=True))

                for alias in vulnerability.aliases:
                    lines.append(f" - {alias}")

            if vulnerability.summary:
                lines.append(click.style("Vulnerability's Summary:", fg="white", bold=True)
                             + " "
                             + f"{vulnerability.summary}")

            if vulnerability.details:
                lines.append(click.style("Vulnerability's Details:", fg="white", bold=True)
                             + " "
                             + f"{vulnerability.details}")

            if vulnerability.severity:
                lines.append(click.style("Vulnerability's Severity:", fg="white", bold=True)
                             + " "
                             + f"{vulnerability.severity}")

            if vulnerability.references:
                lines.append(click.style("References:", fg="white", bold=True))
                for reference in vulnerability.references[:4]:
                    if isinstance(reference, dict):
                        reference_url = reference.get("url", "UNKNOWN")
                    else:
                        reference_url = reference
                    lines.append(f" - {reference_url}")
        lines.append("-"*60)

    return "\n".join(lines)



def print_rendered_vulnerabilities(rendered_vulnerabilities:str):
    """
    Prints the rendered vulnerabilities using Click.
    Args:
        rendered_vulnerabilities: Output of the render_vulnerabilities function.
    """
    print(rendered_vulnerabilities)