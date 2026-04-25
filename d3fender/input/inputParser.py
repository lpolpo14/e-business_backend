"""
This module is responsible for parsing the json input containing the organization data including the
defensive structure and metadata. For the time being this module handles only files in json format.
"""

import json
import re
from typing import Any, Dict

from d3fender.NLP.SentenceTransformer import DefensesSentenceTransformer

# The following dict is used to map from the inputTemplate to the capabilities.json
RAW_PATH_TO_CAP_ID: Dict[str, str] = {
    # authentication
    "defensive_capabilities.authentication.token_based_authentication": "auth.token_based_authentication",
    "defensive_capabilities.authentication.password_authentication": "auth.password_authentication",
    "defensive_capabilities.authentication.multi-factor_authentication": "auth.multi_factor_authentication",
    "defensive_capabilities.authentication.certificate_based_authentication": "auth.certificate_based_authentication",

    # credential hardening
    "defensive_capabilities.credential_hardening.certificate_pinning": "cred.certificate_pinning",
    "defensive_capabilities.credential_hardening.credential_rotation": "cred.credential_rotation",
    "defensive_capabilities.credential_hardening.token_binding": "cred.token_binding",
    "defensive_capabilities.credential_hardening.revocation": "cred.revocation",
    "defensive_capabilities.credential_hardening.scrubbing": "cred.scrubbing",

    # processes / policies
    "defensive_capabilities.processes_and_policies.password_policy": "proc.password_policy",

    # context
    "threat_context.involves_software_engineering": "ctx.involves_software_engineering",
    "threat_context.public_web_application": "ctx.public_web_application",
    "threat_context.remote_workforce": "ctx.remote_workforce",
    "threat_context.handles_sensitive_data": "ctx.sensitive_data",

    # software engineering hardening
    "defensive_capabilities.application_hardening.address_space_layout_randomization(aslr)": "sw.aslr",
    "defensive_capabilities.application_hardening.stack_frame_canary_validation": "sw.stack_frame_canary_validation",
    "defensive_capabilities.application_hardening.dead_code_elimination": "sw.dead_code_elimination",
    "defensive_capabilities.application_hardening.code_analysis": "sw.code_analysis",
    "defensive_capabilities.application_hardening.input_validation": "sw.input_validation",

    # detection
    "defensive_capabilities.detection.user_behavior_analysis": "detect.user_behavior_analysis",
    "defensive_capabilities.detection.remote_terminal": "detect.remote_terminal",

    # file security
    "defensive_capabilities.file_security.file_hashing": "file.file_hashing",
    "defensive_capabilities.file_security.disk_encryption": "disk.encryption",
    "defensive_capabilities.file_security.file_content_analysis": "file.file_content_analysis",
    "defensive_capabilities.file_security.local_permissions": "file.local_permissions",
    "defensive_capabilities.file_security.executable_allowlisting": "file.executable_allowlisting",

    # deception
    "defensive_capabilities.deception.decoy_environment": "deceive.decoy_environment",

    # communications security
    "defensive_capabilities.communications_security.message_encryption": "msg.message_encryption",

    # database security
    "defensive_capabilities.database_security.query_string_analysis": "db.query_string_analysis",

    # application security
    "defensive_capabilities.application_security.process_isolation": "application.process_isolation",

    # dns security
    "defensive_capabilities.dns_security.dns_allowlisting": "dns.allowlisting",
    "defensive_capabilities.dns_security.dns_denylisting": "dns.denylisting",
    "defensive_capabilities.dns_security.dns_traffic_analysis": "dns.traffic_analysis"
}


RAW_PATH_TO_CONTROL_ID: Dict[str, str] = {
    # network
    "defensive_controls.network_security.firewall": "net.firewall",
    "defensive_controls.network_security.vpn": "net.vpn",

    # access control
    "defensive_controls.access_control.identity_access_management": "access.identity_access_management",

    # detection
    "defensive_controls.detection.security_monitoring": "detect.security_monitoring",

    # identity
    "defensive_controls.identity.session_credential_management": "identity.session_credential_management",

    # endpoint security
    "defensive_controls.endpoint_security.antivirus": "detect.antivirus"
}

def retrieveInputJsonDataFromFile(pathInputFile : str) -> dict:
    """
        Retrieves the entire JSON dict from the input file.
        Args:
            pathInputFile: The path (Absolute or Relative) to the JSON input file.
        Returns:
            A JSON dictionary containing the organization's defensive structure and metadata
    """
    inputJSONdata = dict()
    with open(pathInputFile) as json_file:
        inputJSONdata = json.load(json_file)
    return inputJSONdata

def retrieve_registry_data_from_file(pathInputFile : str) -> dict:
    """
    Retrieves the entire JSON dict from the registry file.
    Args:
        pathInputFile: The path (Absolute or Relative) to the JSON input file.
    Returns:
        A JSON dictionary containing the registry (index) of all the noted capabilities
    """
    inputJSONdata = dict()
    with open(pathInputFile) as json_file:
        inputJSONdata = json.load(json_file)
    return inputJSONdata

def retrieveInputJsonDataFromString(data : str) -> dict:
    """
        Retrieves the entire JSON dict from the string.
        Args:
            data: the JSON content of the input file.
        Returns:
            A JSON dictionary containing the organization's defensive structure and metadata
    """
    return json.loads(data)

def parseInputJsonDataFile_onlyLeaves(jsonData : dict) -> dict:
    """
        Retrieves the leaf key-values of the JSON Dictionary.
        Args:
            jsonData: A dictionary object that will be parsed
        Returns:
            A JSON Dictionary of only one layer consisting sole of leaf key-values pairs.
    """
    leaves = {}
    def parse(obj):
        if isinstance(obj, dict):
            for key,value in obj.items():
                if isinstance(value, dict):
                    parse(value)
                else:
                    leaves[key] = value
    parse(jsonData)
    return leaves

def flatten_json_paths(jsonData: Any, prefix: str = "") -> dict:
    """
        Recursively Flattens JSON into dot path keys.
        Example: {"a":{"b":true}} -> {"a.b": true}
        Args:
            jsonData:
            prefix:
    Returns:
    """
    out = {}

    def rec(x: Any, p: str) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                np = f"{p}.{k}" if p else k
                rec(v, np)
        else:
            out[p] = x

    rec(jsonData, prefix)
    # Ensure it is dictionary
    return {k: v for k, v in out.items() if k}

def get_capabilities_defaults_from_registry(registry: Dict[str, Any]) -> Dict[str, Any]:
    """

    Args:
        registry: The parsed JSON registry

    Returns:
        A dictionary containing the default values for all capabilities.
    """
    caps: Dict[str, Any] = {}
    for c in registry.get("capabilities", []):
        cid = c.get("id")
        if cid:
            caps[cid] = c.get("default", False)
    return caps

def get_controls_defaults_from_registry(registry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Retrieves the controls from the registry
    Args:
        registry: The parsed JSON registry

    Returns:
    A dictionary containing the default values for all controls.
    """
    controls: Dict[str, Any] = {}
    for c in registry.get("controls", []):
        cid = c.get("id")
        if cid:
            controls[cid] = c.get("default", False)
    return controls

def normalize_json_input_to_capabilities(raw_input: Dict[str, Any],
                                    capabilities_registry: Dict[str, Any],
                                    controls_registry: Dict[str, Any],
                                    capabilities_mapping: Dict[str, str] = RAW_PATH_TO_CAP_ID,
                                    controls_mapping: Dict[str, str] = RAW_PATH_TO_CONTROL_ID) -> Dict[str, Any]:
    """
    Input normalizer - Given user inputs (JSON) translate to capabilities from capabilities.json.
    Args:
        controls_registry:
        raw_input:  The input given by the user.
        capabilities_registry:  The parsed JSON registry.
        capabilities_mapping: A dictionary containing the mapping of capabilities (From Template to capabilities.json).
    Returns:
        A dictionary containing the capabilities normalized.
    """
    flattened_input = flatten_json_paths(raw_input)
    capabilities = get_capabilities_defaults_from_registry(capabilities_registry)
    for raw_path, capability_id in capabilities_mapping.items():
        if raw_path in flattened_input:
            capabilities[capability_id] = flattened_input[raw_path]
    # Add and if statement here in order to allow user to set precedence over controls vs capabilities
    controls = get_controls_defaults_from_registry(controls_registry)
    for raw_path, control_id in controls_mapping.items():
        if raw_path in flattened_input:
            controls[control_id] = flattened_input[raw_path]
    apply_capabilities_from_controls(controls, capabilities, controls_registry)

    canonical = {
        "metadata": raw_input.get("metadata", {}),
        "environment": raw_input.get("environment", {}), # Remove
        "threat_context": raw_input.get("threat_context", {}),
        "assets": raw_input.get("assets", []), # Remove
        "capabilities": capabilities,
        "controls": controls,
    }
    return canonical

def apply_capabilities_from_controls(controls, capabilities, controls_registry):
    for control_id, enabled in controls.items():
        if enabled:
            for capability_id in get_capabilities_coverage(control_id, controls_registry):
                capabilities[capability_id] = True

def get_capabilities_coverage(control_id, controls_registry):
    controls = controls_registry.get("controls", [])
    for control in controls:
        if control.get("id") == control_id:
            return control.get("covers_capabilities", [])
    return []

def normalize_plaintext_input_to_capabilities(text_input: str,
                                              capabilities_registry: Dict[str, Any],
                                              controls_registry: Dict[str, Any],
                                              semanticIndex: DefensesSentenceTransformer,
                                              threshold : float = 0.4) -> Dict[str, Any]:
    """
    Input normalizer - Given Plain Text Input (txt) translate to capabilities from capabilities.json.
    Args:
        text_input: The plain text input given by the user.
        registry: The parsed JSON registry.
        semanticIndex:
        threshold:
    Returns:
        A dictionary containing the capabilities normalized.
    """
    capabilities = get_capabilities_defaults_from_registry(capabilities_registry)
    controls = get_controls_defaults_from_registry(controls_registry)

    # Split input text into spans based on lines as well as punctuations
    spans = []
    for line in text_input.splitlines():
        line = line.strip()
        if not line:
            continue
        spans.extend([span.strip() for span in re.split(r"[.;,]+", line) if span.strip()])

    alias_map = build_alias_map(capabilities_registry, controls_registry)
    unresolved = [] # In case no matches
    for span in spans:
        cid, alias = alias_match(span, alias_map)
        if cid: # If there was a match
            if cid in capabilities:
                capabilities[cid] = (not isNegated(span))
            else:
                controls[cid] = (not isNegated(span))
            # Add Explainability / Evidence later here.
            continue

        candidates = semanticIndex.query(span)
        best_id, best_score = candidates[0]

        if best_score > threshold:
            negative = isNegated(span)
            if best_id in capabilities:
                capabilities[best_id] = (not negative)
            else:
                controls[best_id] = (not negative)
            # Add Explainability / Evidence later here.
        else:
            unresolved.append({"span": span, "top_matches": candidates})
    apply_capabilities_from_controls(controls, capabilities, controls_registry)
    canonical = {
        "metadata": {},
        "environment": {},
        "threat_context": {},
        "assets": {},
        "capabilities": capabilities,
        "controls": controls,
        "unresolved": unresolved,
    }
    return canonical



Negatives = {"no", "not", "lacking", "missing", "none", "negative"}
def isNegated(text: str) -> bool:
    """
    Is used to infer whether the input is negated. (Example: 'Firewall is NOT applied' returns True).
    Args:
        text: The input text to check.

    Returns:
        A boolean indicating whether the input is negated.
    """
    span = text.lower()
    return any(re.search(rf"\b{re.escape(w)}\b", span) for w in Negatives)


def build_alias_map_OLD(registry: Dict[str, Any]) -> Dict[str, str]:
    """
    DEPRECATED
        Based on the registry, builds a dictionary where each key is an alias and each value is the capability ID.
    Args:
        registry: The parsed JSON registry containing the capabilities.

    Returns:
        The fully formed alias map.
    """
    alias_map = {}
    for c in registry.get("capabilities", []):
        cid = c["id"]
        for a in c.get("aliases", []):
            alias_map[a.lower()] = cid
    return alias_map

def build_alias_map(capabilities_registry: Dict[str, Any],
                    controls_registry: Dict[str, Any]) -> Dict[str, str]:
    """
    DEPRECATED
        Based on the registry, builds a dictionary where each key is an alias and each value is the capability ID.
    Args:
        registry: The parsed JSON registry containing the capabilities.

    Returns:
        The fully formed alias map.
    """
    alias_map = {}
    for c in capabilities_registry.get("capabilities", []):
        cid = c["id"]
        for a in c.get("aliases", []):
            alias_map[a.lower()] = cid
    for c in controls_registry.get("controls", []):
        cid = c["id"]
        for a in c.get("aliases", []):
            alias_map[a.lower()] = cid
    return alias_map

def alias_match(span: str, alias_map : Dict[str, str]) -> tuple[str, str] | tuple[None, None]:
    """
        Checks if there is a capability whose alias matches the given span/text input.
    Args:
        span: The string for which to check if an alias matches.
        alias_map: The alias map from which all aliases are retrieved.

    Returns:
        IF span matches alies -> Returns the Capability ID as well as the alias that matched.
        ELSE Returns an empty tuple.
    """
    s = span.lower()
    for alias in sorted(alias_map.keys(), key=len, reverse=True):
        if re.search(rf"\b{re.escape(alias)}\b", s):
            return alias_map[alias], alias
    return None, None