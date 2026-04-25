"""
Main definition and structure of a rule. The most important aspect of the rule based system.
"""
from typing import Callable

class Rule:
    """
    Represents a rule. Each rule has a strict structure and is hardcoded to preserve transparency and deterministic behaviour.
    A rule is satisfied when its conditions are fulfilled - in that case there is a missing capability as
    described by the specific missingCapability Field. For each rule there are hardcoded D3FEND and ATT&CK
    Techniques. Other ATT&CK Techniques may be derived using the D3FEND techniques and the Knowledge Base.
    """
    def __init__(self,
                 ruleID: str,
                 title: str,
                 description: str,
                 conditions: Callable,
                 missing_capabilities: list[str],
                 evidence_fields: list[str],
                 attack_techniques: list,
                 d3fend_techniques: list,
                 recommendation: str,
                 severity: str = "medium") -> None:
        """
        Initializer Function for a rule.

        Args:
            ruleID: Identifier for the rule. Desired format is CATEGORY.TITLE.SHORT_DESCRIPTION .
            description: A short description of the missing capability.
            conditions: a lambda function with one parameter of dict type. The function contains AND, OR, XOR etc. conditions
            that need to hold true for the specific rule to be true. Example: (lambda input: input["token_based_authentication"] and (not input["token_binding"]))
            missing_capabilities: The missing capability, closely correlated to the D3FEND Techniques.
            attack_techniques: A list of Strings which contain the correlated ATT&CK IDs (T___). Can be derived algorithmically.
            d3fend_techniques: A list of Strings which contain the correlated D3FEND Ids (D3-___).
            recommendation: A string that describes the recommendation of the rule.
            evidence_fields: Contains the evidence fields (capabilities from registry) for explainability purposes.
            severity: A string that describes the severity of the rule.
        """
        self.ruleID = ruleID
        self.title = title
        self.description = description
        self.conditions = conditions
        self.evidence_fields = evidence_fields
        self.severity = severity
        self.missing_capabilities = missing_capabilities
        self.attack_techniques = attack_techniques
        self.d3fend_techniques = d3fend_techniques
        self.recommendation = recommendation

    def applies(self, capabilities: dict) -> bool:
        """
        Evaluates whether a rule applies based on the given organizational input

        Args:
            capabilities: Parsed JSON representation of the organization's defensive status.
        Returns:
            True if the rule conditions apply, otherwise False.
        """
        return self.conditions(capabilities)

# Now thinking about it - why did I implement getters in Python ...
    def getRuleID(self) -> str:
        """
        Returns the ruleID of the object
        """
        return self.ruleID

    def getDescription(self) -> str:
        """
        Returns the description of the object
        """
        return self.description

    def getMissingCapability(self) -> list:
        """
        Returns the missing capability of the object
        """
        return self.missing_capabilities

    def getAttackTechniques(self) -> list:
        """
        Returns a list of string containing ATT&CK techniques
        """
        return self.attack_techniques

    def getD3fendTechniques(self) -> list:
        """
        Returns a list of string containing D3FEND techniques
        """
        return self.d3fend_techniques