"""Static Suricata signature -> MITRE ATT&CK mapping.

Keyed by the exact `msg` text of each rule in suricata.rules/custom.rules
(the same string Suricata reports as alert.signature, which
suricata_logger.py stores as suricata_alerts.alert_sig). Looked up at
insert time in suricata_logger.py and used to backfill historical rows.

Deliberately app-side rather than relying on Suricata's rule `metadata`
keyword + eve-log `metadata: yes`: it works retroactively on rows already
in the DB, doesn't depend on an eve-log config/restart, and keeps rule
text and MITRE bookkeeping in one auditable place.
"""

_ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


def _t(tactic, technique_id, technique_name):
    slug = technique_id.replace(".", "/")
    return {
        "mitre_tactic": tactic,
        "mitre_technique": technique_id,
        "mitre_technique_name": technique_name,
        "mitre_url": _ATTACK_URL.format(slug),
    }


SIGNATURE_MITRE = {
    # --- Port Scan Detection (Reconnaissance) ---
    "HONEYPOT SSH Connection Attempt": _t("Reconnaissance", "T1595", "Active Scanning"),
    "HONEYPOT HTTP Connection Attempt": _t("Reconnaissance", "T1595", "Active Scanning"),
    "HONEYPOT FTP Connection Attempt": _t("Reconnaissance", "T1595", "Active Scanning"),
    "HONEYPOT Telnet Connection Attempt": _t("Reconnaissance", "T1595", "Active Scanning"),
    "HONEYPOT SMTP Connection Attempt": _t("Reconnaissance", "T1595", "Active Scanning"),
    "HONEYPOT Redis Connection Attempt": _t("Reconnaissance", "T1595", "Active Scanning"),
    "HONEYPOT MySQL Connection Attempt": _t("Reconnaissance", "T1595", "Active Scanning"),
    "HONEYPOT PostgreSQL Connection Attempt": _t("Reconnaissance", "T1595", "Active Scanning"),
    "HONEYPOT HTTPS Connection Attempt": _t("Reconnaissance", "T1595", "Active Scanning"),

    # --- HTTP Exploit Probes (Initial Access / Persistence) ---
    "HONEYPOT WordPress wp-login.php Probe": _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "HONEYPOT .env File Disclosure Probe": _t("Credential Access", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    "HONEYPOT PHP Webshell Probe": _t("Persistence", "T1505.003", "Server Software Component: Web Shell"),
    "HONEYPOT Shell Command in HTTP Body": _t("Command and Control", "T1105", "Ingress Tool Transfer"),

    # --- Redis Exploitation (Lateral Movement / Execution / Persistence) ---
    "HONEYPOT Redis CONFIG SET Attack": _t("Lateral Movement", "T1210", "Exploitation of Remote Services"),
    "HONEYPOT Redis SLAVEOF Attack": _t("Lateral Movement", "T1210", "Exploitation of Remote Services"),
    "HONEYPOT Redis EVAL Code Execution": _t("Execution", "T1059", "Command and Scripting Interpreter"),
    "HONEYPOT Redis Cron Payload": _t("Persistence", "T1053.003", "Scheduled Task/Job: Cron"),

    # --- Reverse Shell Payloads (Execution) ---
    "HONEYPOT Reverse Shell /dev/tcp": _t("Execution", "T1059.004", "Unix Shell"),
    "HONEYPOT Reverse Shell bash -i": _t("Execution", "T1059.004", "Unix Shell"),
    "HONEYPOT Netcat Reverse Shell": _t("Execution", "T1059.004", "Unix Shell"),

    # --- Download Attempts (Command and Control) ---
    "HONEYPOT wget Download Attempt": _t("Command and Control", "T1105", "Ingress Tool Transfer"),
    "HONEYPOT curl Download Attempt": _t("Command and Control", "T1105", "Ingress Tool Transfer"),

    # --- Post-Exploitation Discovery ---
    "HONEYPOT Recon - System Info Command (uname)": _t("Discovery", "T1082", "System Information Discovery"),
    "HONEYPOT Recon - Passwd File Read": _t("Discovery", "T1087.001", "Account Discovery: Local Account"),
    "HONEYPOT Recon - Process List Command": _t("Discovery", "T1057", "Process Discovery"),
    "HONEYPOT Recon - Network Config Command": _t("Discovery", "T1016", "System Network Configuration Discovery"),

    # --- Persistence ---
    "HONEYPOT Persistence - SSH Authorized Keys Write": _t("Persistence", "T1098.004", "Account Manipulation: SSH Authorized Keys"),
    "HONEYPOT Persistence - Crontab Modification": _t("Persistence", "T1053.003", "Scheduled Task/Job: Cron"),
    "HONEYPOT Persistence - Account Creation": _t("Persistence", "T1136.001", "Create Account: Local Account"),

    # --- Privilege Escalation / Defense Evasion ---
    "HONEYPOT Privilege Escalation - SUID Bit Set": _t("Privilege Escalation", "T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid"),
    "HONEYPOT Defense Evasion - Command History Cleared": _t("Defense Evasion", "T1070.003", "Indicator Removal: Clear Command History"),
    "HONEYPOT Defense Evasion - Log File Deletion": _t("Defense Evasion", "T1070.002", "Indicator Removal: Clear Linux or Mac System Logs"),
    "HONEYPOT Defense Evasion - Base64 Decode-and-Execute": _t("Defense Evasion", "T1027", "Obfuscated Files or Information"),

    # --- Impact (Cryptomining) ---
    "HONEYPOT Impact - Cryptominer Binary Reference": _t("Impact", "T1496", "Resource Hijacking"),
    "HONEYPOT Impact - Mining Pool Connection String": _t("Impact", "T1496", "Resource Hijacking"),

    # --- Command and Control (refined) ---
    "HONEYPOT C2 - Download Piped Directly to Shell": _t("Command and Control", "T1105", "Ingress Tool Transfer"),

    # --- Web Initial Access (expanded) ---
    "HONEYPOT Log4Shell JNDI Probe": _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "HONEYPOT Path Traversal Probe": _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "HONEYPOT Common Webshell Filename Probe": _t("Persistence", "T1505.003", "Server Software Component: Web Shell"),
    "HONEYPOT Git Config Disclosure Probe": _t("Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    "HONEYPOT SQL Injection Probe": _t("Initial Access", "T1190", "Exploit Public-Facing Application"),
}


def lookup(alert_sig):
    """Returns the MITRE dict for a signature, or all-None fields if unmapped
    (e.g. a rule added later through the dashboard's rule builder)."""
    return SIGNATURE_MITRE.get(alert_sig) or {
        "mitre_tactic": None,
        "mitre_technique": None,
        "mitre_technique_name": None,
        "mitre_url": None,
    }
