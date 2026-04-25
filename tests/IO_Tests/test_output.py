"""
This module focuses on testing the various output handler methods
that improve the user experience.
"""
from d3fender.IO import Output
from d3fender.rules.ruleClass import Rule


def test_ListOfRulesToListOfDicts():
    """
    Not really useful
    Tests the function RulesToListDictionaries
    """
    from d3fender.rules import ruleClass

    rule1 = Rule(
        ruleID="AUTH.TOKEN_BINDING.MISSING",
        title="Missing Token Binding",
        description="Token-based authentication is present, but token binding is absent.",
        conditions=lambda cap: cap["auth.token_based_authentication"]
                               and (not cap["cred.token_binding"]),
        missing_capabilities=["cred.token_binding"],
        evidence_fields=[
            "auth.token_based_authentication",
            "cred.token_binding",
        ],
        attack_techniques=["T1041", "T1071.001", "T1557"],
        d3fend_techniques=["D3-CP", "D3-CA"],
        recommendation=(
            "Enable token binding or an equivalent proof-of-possession mechanism "
            "for token-based authentication flows."
        ),
        severity="high",
    )

    rule2 = Rule(
        ruleID="AUTH.PASSWORD_POLICY.XOR_CRED_ROTATION",
        title="Incomplete Credential Hardening Policy",
        description="Password policy and credential rotation are not implemented together.",
        conditions=lambda cap: cap["proc.password_policy"] ^ cap["cred.credential_rotation"],
        missing_capabilities=["proc.password_policy", "cred.credential_rotation"],
        evidence_fields=[
            "proc.password_policy",
            "cred.credential_rotation",
        ],
        attack_techniques=["T1110", "TA0006"],
        d3fend_techniques=["D3-SSP", "D3-CRO"],
        recommendation=(
            "Apply both a formal password policy and credential rotation controls "
            "to improve credential hardening."
        ),
        severity="medium",
    )

    testList = []
    testList.append(rule1)
    testList.append(rule2)
    output = Output.RulesToListDictionaries(testList)
    assert len(output) == 2
    assert output[0]["rule"] == "Token-based authentication is present, but token binding is absent."
    assert output[0]["attackTechniques"] == "T1041, T1071.001, T1557"
    assert output[1]["rule"] == "Password policy and credential rotation are not implemented together."
