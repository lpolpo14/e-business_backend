"""
Main definition of a finding - based on rule evaluation.
"""
from dataclasses import dataclass, field

@dataclass
class Finding:
    """
    Represents a finding from the main assessment. It is used in rule evaluation.
    It is used to ensure explainability of the System, as well as structured output.
    """
    rule_id: str
    title: str
    description: str
    severity: str
    recommendation: str
    missing_capabilities: list[str]
    attack_techniques: list[str]
    d3fend_techniques: list[str]
    evidence: dict = field(default_factory=dict)