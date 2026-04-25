"""
This module is responsible for evaluating the various rules based on the user input.
"""
from d3fender.rules.Finding import Finding


def evaluateRules(input: dict, rules: list) -> list:
    """
    The main rule evaluator which conducts the gap analysis. Based on the organization's defenses and structure given in the input,
    the evaluator ascertains which rules are active, meaning what defenses are missing. It returns a list of Findings, which help ensure explainability.
    Args:
        input: The defenses given in parsed dictionary form.
        rules: A list of rules that are to be taken into account during the evaluation
    Returns:
        A list containing all the Findings (missing defenses)
    """
    findings = []
    capabilities = input['capabilities']
    for rule in rules:
        if rule.applies(capabilities):
            evidence = {
                field: capabilities.get(field, None)
                for field in rule.evidence_fields
            }

            finding = Finding(
                rule_id=rule.ruleID,
                title=rule.title,
                description=rule.description,
                severity=rule.severity,
                recommendation=rule.recommendation,
                missing_capabilities=rule.missing_capabilities,
                attack_techniques = rule.attack_techniques,
                d3fend_techniques = rule.d3fend_techniques,
                evidence=evidence
            )

            findings.append(finding)

    return findings

