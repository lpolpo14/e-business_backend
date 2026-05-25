"""
Dataclasses representing SBOM related objects
"""
from dataclasses import dataclass, field


@dataclass
class SBOMComponent:
    """
    Represents a SBOM component.
    """
    bom_ref: str
    name: str | None
    version: str | None
    purl: str | None
    version: str | None
    type: str | None
    licenses: list[str] = field(default_factory=list) # Avoids issues with mutable shared lists

@dataclass
class SBOMVulnerability:
    """
    Represents a specific vulnerability detected within a SBOM component.
    """
    component: SBOMComponent
    vulnerability_id: str
    summary: str | None
    details: str | None
    severity: str | None
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)