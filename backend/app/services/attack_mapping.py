"""
MITRE ATT&CK static mapping — Niveau 1
Associe chaque catégorie de vulnérabilité à une ou plusieurs techniques ATT&CK.
"""

from typing import List, Dict, Any

# Mapping: category (lowercase) → liste de techniques ATT&CK
ATTACK_MAPPING: Dict[str, List[Dict[str, str]]] = {
    # Injection
    "injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "sql injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "command injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "ldap injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
    ],

    # XSS
    "xss": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"},
    ],
    "cross-site scripting": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"},
    ],

    # Authentication & Session
    "authentication": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "broken authentication": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "session management": [
        {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access"},
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"},
    ],
    "cookie": [
        {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access"},
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"},
    ],

    # Information Disclosure
    "information disclosure": [
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    ],
    "sensitive data": [
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "data exposure": [
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],

    # Security Misconfiguration
    "misconfiguration": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    ],
    "security misconfiguration": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    ],
    "http headers": [
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Collection"},
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
    ],

    # SSL/TLS
    "ssl": [
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Collection"},
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
    ],
    "tls": [
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Collection"},
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
    ],
    "certificate": [
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Collection"},
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
    ],

    # CSRF
    "csrf": [
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"},
        {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    ],
    "cross-site request forgery": [
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"},
        {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    ],

    # Open Redirect
    "redirect": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
        {"id": "T1598", "name": "Phishing for Information", "tactic": "Reconnaissance"},
    ],
    "open redirect": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
        {"id": "T1598", "name": "Phishing for Information", "tactic": "Reconnaissance"},
    ],

    # Network
    "open port": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "service": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "banner": [
        {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],

    # Exposed endpoints
    "exposed": [
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "directory listing": [
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],

    # Default
    "default": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
}


def get_attack_techniques(category: str) -> List[Dict[str, str]]:
    """Retourne les techniques ATT&CK correspondant à une catégorie de vulnérabilité."""
    if not category:
        return ATTACK_MAPPING["default"]

    cat_lower = category.lower()

    # Exact match
    if cat_lower in ATTACK_MAPPING:
        return ATTACK_MAPPING[cat_lower]

    # Partial match
    for key in ATTACK_MAPPING:
        if key == "default":
            continue
        if key in cat_lower or cat_lower in key:
            return ATTACK_MAPPING[key]

    return ATTACK_MAPPING["default"]
