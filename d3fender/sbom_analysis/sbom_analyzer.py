"""
Orchestrates the entire sbom analysis procedure.
"""
import click

from d3fender.sbom_analysis.osv_handlers import query_OSV_for_component
from d3fender.sbom_analysis.sbom_models import SBOMComponent, SBOMVulnerability
from d3fender.sbom_analysis.sbom_parser import retrieveSBOM_content, parseSBOM_components


def analyze_sbom(file):
    """
    Main sbom analyzer function.
    Args:
        file: The json file from which sbom is read
    Returns:
        A list of SBOM related objects.
    """
    content = retrieveSBOM_content(file)
    components = parseSBOM_components(content)
    return components

def find_components_vulnerabilities(components:list[SBOMComponent]) -> dict[str, list[SBOMVulnerability]]:
    """
    Detects vulnerabilities for the provided SBOM components
    Args:
        components: The components of a specific SBOM file.
    Returns:
        A dict of vulnerabilities mapped to their SBOM Component.
    """
    results = {}
    with click.progressbar(components,label="Querying OSV for vulnerabilities") as progress_components:
        for component in progress_components:
            vulns = query_OSV_for_component(component)
            if vulns:
                results[component.bom_ref] = vulns
    return results

