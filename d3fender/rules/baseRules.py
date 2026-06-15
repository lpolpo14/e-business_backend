"""
Contains the base rules used for the first prototype of the application.
"""
from .ruleClass import Rule

AllRULES = []

TokenBindingRULE = Rule(
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
    d3fend_techniques=["D3-TBA", "D3-TB"],
    recommendation=(
        "Enable token binding or an equivalent proof-of-possession mechanism "
        "for token-based authentication flows."
    ),
    severity="high",
)

AllRULES.append(TokenBindingRULE)


PasswordPolicyRULE = Rule(
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

AllRULES.append(PasswordPolicyRULE)

StackOverflowRULE = Rule(
    ruleID="SOFT_ENG.STACK_OVERFLOW.MISSING_HARDENING",
    title="Missing Stack Overflow Mitigations",
    description="Software engineering is involved, but exploit mitigation controls for memory corruption are absent.",
    conditions=lambda cap: cap["ctx.involves_software_engineering"]
                           and (not cap["sw.aslr"])
                           and (not cap["sw.stack_frame_canary_validation"]),
    missing_capabilities=["sw.aslr", "sw.stack_frame_canary_validation"],
    evidence_fields=[
        "ctx.involves_software_engineering",
        "sw.aslr",
        "sw.stack_frame_canary_validation",
    ],
    attack_techniques=["T1068", "T1190"],
    d3fend_techniques=["D3-SAOR", "D3-SFCV"],
    recommendation=(
        "Enable exploit mitigation controls such as ASLR and stack frame canary "
        "validation in relevant software components."
    ),
    severity="high",
)

AllRULES.append(StackOverflowRULE)

DeadCodeRULE = Rule(
    ruleID="SOFT_ENG.DEAD_CODE.MISSING_CONTROLS",
    title="Missing Code Minimization and Analysis Controls",
    description="Software engineering is involved, but both dead-code elimination and code analysis are absent.",
    conditions=lambda cap: cap["ctx.involves_software_engineering"]
                           and (not cap["sw.dead_code_elimination"])
                           and (not cap["sw.code_analysis"]),
    missing_capabilities=["sw.dead_code_elimination", "sw.code_analysis"],
    evidence_fields=[
        "ctx.involves_software_engineering",
        "sw.dead_code_elimination",
        "sw.code_analysis",
    ],
    attack_techniques=["T1068", "T1055"],
    d3fend_techniques=["D3-DCE", "D3-SCH"],
    recommendation=(
        "Introduce dead-code elimination and static code analysis practices "
        "within the software development lifecycle."
    ),
    severity="medium",
)

AllRULES.append(DeadCodeRULE)

RemoteMFARULE = Rule(
    ruleID="AUTH.MFA.REMOTE_WORKFORCE.MISSING",
    title="Missing MFA for Remote Workforce",
    description="Remote access or distributed workforce context is present, but multi-factor authentication is absent.",
    conditions=lambda cap: cap["ctx.remote_workforce"]
                           and (not cap["auth.multi_factor_authentication"]),
    missing_capabilities=["auth.multi_factor_authentication"],
    evidence_fields=[
        "ctx.remote_workforce",
        "auth.multi_factor_authentication",
    ],
    attack_techniques=["T1078", "T1110"],
    d3fend_techniques=["D3-MFA"],
    recommendation=(
        "Introduce multi-factor authentication for remote authentication procedues"
    ),
    severity="high",
)

AllRULES.append(RemoteMFARULE)

TokenRevocationRULE = Rule(
    ruleID="AUTH.TOKEN_REVOCATION.MISSING",
    title="Missing Token Revocation",
    description="Token-based authentication is used, but credential revocation is absent.",
    conditions=lambda cap: cap["auth.token_based_authentication"]
                           and (not cap["cred.revocation"]),
    missing_capabilities=["cred.revocation"],
    evidence_fields=[
        "auth.token_based_authentication",
        "cred.revocation",
    ],
    attack_techniques=["T1134", "T1134.001", "T1539"],
    d3fend_techniques=["D3-CR"],
    recommendation=(
        "Introduce token and session revocation mechanisms so compromised or stale "
        "authentication artifacts can be invalidated promptly."
    ),
    severity="high",
)

AllRULES.append(TokenRevocationRULE)


InternetFacingInputValidationRULE = Rule(
    ruleID="SOFT_ENG.INPUT_VALIDATION.INTERNET_FACING.MISSING",
    title="Missing Input Validation for Internet-Facing Services",
    description="Internet-facing services are present, but input validation controls are absent.",
    conditions=lambda cap: cap["ctx.public_web_application"]
                            and cap["ctx.involves_software_engineering"]
                           and (not cap["sw.input_validation"]),
    missing_capabilities=["d3fend.input_validation"],
    evidence_fields=[
        "ctx.public_web_application",
        "ctx.involves_software_engineering",
        "sw.input_validation",
    ],
    attack_techniques=["T1190"],
    d3fend_techniques=["D3-CV", "D3-UBA"],
    recommendation=(
        "Apply input validation and sanitization controls on externally "
        "accessible services and application entry points."
    ),
    severity="high",
)

AllRULES.append(InternetFacingInputValidationRULE)


SensitiveDataUebaRULE = Rule(
    ruleID="DETECT.UEBA.SENSITIVE_DATA.MISSING",
    title="Missing User Behavior Analysis in Sensitive Data Environment",
    description="Sensitive data is handled, but user behavior analysis is absent.",
    conditions=lambda cap: cap["ctx.public_web_application"]
                           and (not cap["detect.user_behavior_analysis"]),
    missing_capabilities=["detect.user_behavior_analysis"],
    evidence_fields=[
        "ctx.public_web_application",
        "detect.user_behavior_analysis",
    ],
    attack_techniques=["T1078", "T1021", "T1110"],
    d3fend_techniques=["D3-UBA"],
    recommendation=(
        "Introduce user behavior analysis to improve visibility into suspicious account activity around sensitive data."
    ),
    severity="medium",
)

AllRULES.append(SensitiveDataUebaRULE)

DecoyEnvironmentRULE = Rule(
    ruleID="DECEIVE.DECOY_ENVIRONMENT.MISSING",
    title="Missing Decoy Environment",
    description="No Decoy Environment is implemented in order to deceive potential attackers.",
    conditions=lambda cap: (not cap["deceive.decoy_environment"]),
    missing_capabilities=["deceive.decoy_environment"],
    evidence_fields=["deceive.decoy_environment"],
    attack_techniques=["T1082"],
    d3fend_techniques=["D3-DE"],
    recommendation=("Introduce a Decoy Environment that comprises of "
                    "hosts and networks for the purposes of deceiving an attacker."),
    severity="low"
)

AllRULES.append(DecoyEnvironmentRULE)

FileSafetyRULE = Rule(
    ruleID="FILE.SAFETY.MISSING",
    title="Missing Malware Detection Capabilities",
    description="No Malware Detection Capabilities are present, nor is File Analysis implemented.",
    conditions=lambda cap: (not cap["file.file_hashing"])
                        and (not cap["file.file_content_analysis"]),
    missing_capabilities=["file.file_hashing", "file.file_content_analysis"],
    evidence_fields=["file.file_hashing", "file.file_content_analysis"],
    attack_techniques=["T1587.001", "T1204.002"],
    d3fend_techniques=["D3-FH", "D3-FCOA"],
    recommendation=("Introduce Malware Detection Capabilities."
                    " Specifically the use of an antivirus system is recommended."),
    severity="medium"
)

AllRULES.append(FileSafetyRULE)

DNSListingRULE= Rule(
    ruleID="DNS.ANALYSIS.MISSING",
    title="Missing DNS Traffic Analysis Mechanisms",
    description="No DNS Protection Mechanisms are employed",
    conditions=lambda cap: (not cap["dns.traffic_analysis"])
        or (not cap["dns.denylisting"] and not cap["dns.allowlisting"]),
    missing_capabilities=["dns.denylisting", "dns.allowlisting", "dns.traffic_analysis"],
    evidence_fields=["dns.traffic_analysis", "dns.allowlisting", "dns.denylisting"],
    attack_techniques=["T1071.004", "T1568"],
    d3fend_techniques=["D3-DNSAL", "D3-DNSDL", "D3-DNSTA"],
    recommendation=("Employ DNS Traffic Analysis Mechanisms, including DNS Denylisting and Allowlisting "
                    "in order to block malicious domains and allow approved domains and DNS Traffic."),
    severity="medium"
)

AllRULES.append(DNSListingRULE)

MessageEncrytionRULE = Rule(
    ruleID="MESSAGE.ENCRYPTION.MISSING",
    title="Missing Message Encryption",
    description="No Message Encryption is present",
    conditions=lambda cap: (not cap["msg.message_encryption"]),
    missing_capabilities=["msg.message_encryption"],
    evidence_fields=["msg.message_encryption"],
    attack_techniques=["T1040"],
    d3fend_techniques=["D3-MENCR"],
    recommendation=("Introduce Message Encryption Mechanisms. "
                    "Without encryption sensitive information is readable by a potential malicious user and sniffers."),
    severity="high"
)

AllRULES.append(MessageEncrytionRULE)

TunnelEncryptionRULE = Rule(
    ruleID="TUNNEL.ENCRYPTION.MISSING",
    title="Missing Tunnel Encryption (VPN)",
    description="No Tunnel Encryption or VPN is present",
    conditions=lambda cap: (not cap["net.encrypted_tunnels"]),
    missing_capabilities=["net.encrypted_tunnels"],
    evidence_fields=["net.encrypted_tunnels"],
    attack_techniques=["T1040", "T1557"],
    d3fend_techniques=["D3-ET"],
    recommendation="Introduce Tunnel Encryption Mechanisms like a VPN which grandly improve network safety.",
    severity="high"
)

AllRULES.append(TunnelEncryptionRULE)

TerminalSessionDetectionRULE = Rule(
    ruleID="REMOTE_TERMINAL_SESSION.DETECTION.MISSING",
    title="Missing Remote Terminal Session Detection",
    description="No Remote Terminal Session Detection is present",
    conditions=lambda cap: cap["ctx.remote_workforce"] and (not cap["detect.remote_terminal"]),
    missing_capabilities=["detect.remote_terminal"],
    evidence_fields=["detect.remote_terminal", "ctx.remote_workforce"],
    attack_techniques=["T1219"],
    d3fend_techniques=["D3-RTSD"],
    recommendation="Since a remote workforce is in works "
                   "implement a remote remote terminal session detection mechanism"
                   " to monitor suspicious activity",
    severity="medium"
)

AllRULES.append(TerminalSessionDetectionRULE)

CredentialScrubbingRULE = Rule(
    ruleID="CREDENTIALS.SCRUBBING.MISSING",
    title="Missing Credential Scrubbing",
    description="No Credential Scrubbing is present, increasing chance of Credential Harvesting",
    conditions=lambda cap: cap["ctx.involves_software_engineering"] and
                           (not cap["cred.scrubbing"]),
    missing_capabilities=["cred.scrubbing"],
    evidence_fields=["ctx.involves_software_engineering","cred.scrubbing"],
    attack_techniques=["T1505"],
    d3fend_techniques=["D3-CS"],
    recommendation="Implement Credential Scrubbing Mechanisms in order to avoid "
                   "leaking secrets like API Keys, tokens and passwords.",
    severity="high"
)

AllRULES.append(CredentialScrubbingRULE)

QueryAnalysisRULE = Rule(
    ruleID="DB_QUERY_STRING.ANALYSIS.MISSING",
    title="Missing Query String Analysis for Data Base",
    description="No Query String Analysis is present for the Data Base, "
                "increasing chance of SQL Injection attacks going unnoticed",
    conditions=lambda cap: cap["ctx.involves_software_engineering"] and
            cap["ctx.public_web_application"] and (not cap["db.query_string_analysis"]),
    missing_capabilities=["db.query_string_analysis"],
    evidence_fields=["ctx.public_web_application", "ctx.involves_software_engineering","db.query_string_analysis"],
    attack_techniques=["T0819"],
    d3fend_techniques=["D3-DQSA"],
    recommendation="Implement Query String Analysis Mechanisms for SQL Databases in order to detect "
                   "and reduce chances of successful SQL injections.",
    severity="high"
)

AllRULES.append(QueryAnalysisRULE)

ApplicationProcessIsolationRULE = Rule(
    ruleID="APPLICATION.PROCESS_ISOLATION.MISSING",
    title="Missing Application Process Isolation (Sandbox)",
    description="No Application Process Isolation is present in order to prevent the application's"
                " own subroutines from accessing intra-process / internal memory space.",
    conditions=lambda cap: cap["ctx.involves_software_engineering"] and
                           (not cap["application.process_isolation"]),
    missing_capabilities=["application.process_isolation"],
    evidence_fields=["ctx.involves_software_engineering","application.process_isolation"],
    attack_techniques=["T1546", "T1053", "T1212"],
    d3fend_techniques=["D3-ABPI"],
    recommendation="Implement Application Process Isolation and use a Sandbox based environment "
                   "to permit or deny a particular subroutine access to other data within the same application "
                   "process. This is intended to prevent critical application process data from being tampered with.",
    severity="high"
)

AllRULES.append(ApplicationProcessIsolationRULE)

LocalFilePermissionsRULE = Rule(
    ruleID="FILE.PERMISSIONS.MISSING",
    title="Missing Local File Permissions",
    description="File Permissions may not be set properly, increasing risk of privilege escalation",
    conditions=lambda cap: (not cap["file.local_permissions"]),
    missing_capabilities=["file.local_permissions"],
    evidence_fields=["file.local_permissions"],
    attack_techniques=["TA0004", "T1204.002", "T1548"],
    d3fend_techniques=["D3-LFP"],
    recommendation="Define, implement, and manage access control policies that dictate user permissions for accessing files ",
    severity="high"
)

AllRULES.append(LocalFilePermissionsRULE)

ExecutableWhitelistingRULE = Rule(
    ruleID="EXECUTABLE.WHITLISTING.MISSING",
    title="Weak Executable Whitelisting - File Signature Authentication",
    description="Though most OS perform File Signature Authentication on their own, malware may still be executed easily",
    conditions=lambda cap: (not cap["file.executable_allowlisting"]),
    missing_capabilities=["file.executable_allowlisting"],
    evidence_fields=["file.executable_allowlisting"],
    attack_techniques=["T1204.002", "T1565.003"],
    d3fend_techniques=["D3-EAL"],
    recommendation="Strengthen File Signature Authentication in order to lessen the chances of malware being executed",
    severity="low"
)

AllRULES.append(ExecutableWhitelistingRULE)

DiskEncryptionRULE = Rule(
    ruleID="DISK.ENCRYPTION.MISSING",
    title="Missing Disk Encryption while handling sensitive data",
    description="Disk Encryption is missing, allowing for cleartext access to the file system",
    conditions=lambda cap: (not cap["disk.encryption"])
            and cap["ctx.sensitive_data"],
    missing_capabilities=["disk.encryption"],
    evidence_fields=["ctx.sensitive_data", "disk.encryption"],
    attack_techniques=["T1619", "T1564"],
    d3fend_techniques=["D3-DENCR"],
    recommendation="Add Disk Encryption to prevent cleartext access to the file system containing sensitive data",
    severity="low"
)

AllRULES.append(DiskEncryptionRULE)

def getAllRules():
    """
            Retrieves all the rules in this file.
    """
    return AllRULES
