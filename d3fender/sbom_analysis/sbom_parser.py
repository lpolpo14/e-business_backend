"""
Parses the SBOM json files and extracts all packages/components of the file.
"""
import json

from d3fender.sbom_analysis.sbom_models import SBOMComponent


def parseSBOM_components(data : json) -> list[SBOMComponent]:
    """
    Parses the SBOM json file and extracts all components into a list.
    Args:
        data: The content of the SBOM file.
    Returns:
        A list containing all SBOM components from provided file content.
    """
    try:
        components = data["components"]
    except KeyError:
        raise KeyError("Error when parsing the SBOM file")
    results = []
    for component in components:
        result = SBOMComponent(
            bom_ref=component["bom-ref"],
            name=component.get("name",None),
            version=component.get("version",None),
            purl=component.get("purl",None),
            type=component.get("type",None),
            licenses=component.get("licenses",None),
        )
        results.append(result)
    return results


def retrieveSBOM_content(sbom_file) -> json:
    """
    Retrieves the contents of the SBOM file
    Args:
        sbom_file: The SBOM file
    Returns:
        The dictionaries containing the SBOM components and dependencies.
    """
    return json.load(sbom_file)