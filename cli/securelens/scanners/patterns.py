import re
from typing import Optional

# VulnerabilityFinding dataclass is imported from securelens.scanners inside functions
# to avoid circular imports.

# ── Regex Rules ──────────────────────────────────────────────────────────────

SECRETS_RULES = [
    {
        "issue": "Hardcoded Private Key",
        "severity": "Critical",
        "regex": re.compile(r"-----BEGIN\s+([A-Z0-9\s_]+)\s+KEY-----", re.IGNORECASE),
        "fix": "Remove the private key from source code and load it from environment variables or a secure key vault.",
        "description": "Exposed private keys allow unauthorized access and cryptographic identity spoofing."
    },
    {
        "issue": "Hardcoded AWS Access Key ID",
        "regex": re.compile(r"\b(AKIA|ASCA|ASIA)[A-Z0-9]{16}\b"),
        "severity": "Critical",
        "fix": "Revoke the exposed key in AWS console and use AWS IAM roles or environment variables for auth.",
        "description": "AWS credentials hardcoded in source code can lead to complete infrastructure compromise."
    },
    {
        "issue": "Hardcoded API/Auth Token",
        "regex": re.compile(r"\b(secret|password|passwd|api_key|apikey|token|private_key|aws_key)\b\s*=\s*['\"]([a-zA-Z0-9_\-\.\+=/]{12,128})['\"]", re.IGNORECASE),
        "severity": "High",
        "fix": "Remove the hardcoded secret and load it dynamically using a secure configuration loader.",
        "description": "Hardcoded credentials can be leaked easily through version control repositories."
    },
    {
        "issue": "Hardcoded Slack Webhook",
        "regex": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}"),
        "severity": "Medium",
        "fix": "Store the Slack webhook in a secure configuration or environment variable.",
        "description": "Exposed Slack webhooks allow malicious actors to post arbitrary messages to your Slack channels."
    }
]

VULNERABILITY_RULES = [
    {
        "issue": "Potential SQL Injection",
        "regex": re.compile(r"\.execute\s*\(\s*(f['\"].*\{\w+\}.*['\"]|['\"].*['\"]\s*\+\s*\w+|.*%\s*\w+)\s*\)", re.IGNORECASE),
        "severity": "High",
        "fix": "Use parameterized queries or ORM query builders instead of raw string formatting/interpolation.",
        "description": "Raw string concatenation in SQL statements allows attackers to manipulate query structures."
    },
    {
        "issue": "Use of Dangerous Function (eval/exec)",
        "regex": re.compile(r"\b(eval|exec)\s*\("),
        "severity": "High",
        "fix": "Refactor the code to avoid executing dynamic string input. Use parser libraries if parsing is required.",
        "description": "Dynamic execution of arbitrary input strings can lead to remote code execution (RCE) vulnerabilities."
    },
    {
        "issue": "Insecure Command Execution (shell=True)",
        "regex": re.compile(r"\bsubprocess\.(Popen|run|call|check_output)\s*\(.*shell\s*=\s*True\b"),
        "severity": "High",
        "fix": "Set shell=False and pass arguments as a list to prevent shell injection vectors.",
        "description": "Invoking the system shell makes the application vulnerable to command injection if input is uncontrolled."
    }
]


def scan_file_content(file_path: str, content: str) -> list:
    """
    Scans code content for secrets and vulnerabilities using static regex patterns.
    Returns a list of VulnerabilityFinding objects.
    """
    from securelens.scanners import VulnerabilityFinding
    findings = []
    lines = content.splitlines()

    # Scan for secrets (entire content or line-by-line)
    for rule in SECRETS_RULES:
        # Check rule match on the entire content first, then find lines
        for match in rule["regex"].finditer(content):
            # Find the line number of the match
            start_index = match.start()
            line_num = content.count('\n', 0, start_index) + 1
            matched_text = match.group(0)
            
            # Simple heuristic: if checking key/secret rule and it's a generic word like "example" or placeholder
            if rule["issue"] == "Hardcoded API/Auth Token":
                val = match.group(2).lower()
                if any(x in val for x in ["placeholder", "example", "dummy", "test", "your_key", "change-me"]):
                    continue  # skip dummy tokens

            findings.append(VulnerabilityFinding(
                file_path=file_path,
                severity=rule["severity"],
                issue=rule["issue"],
                explanation=f"{rule['description']} (Found: '{matched_text[:40]}...')",
                suggested_fix=rule["fix"],
                line_number=line_num
            ))

    # Scan for vulnerabilities line by line
    for line_idx, line in enumerate(lines, 1):
        for rule in VULNERABILITY_RULES:
            if rule["regex"].search(line):
                findings.append(VulnerabilityFinding(
                    file_path=file_path,
                    severity=rule["severity"],
                    issue=rule["issue"],
                    explanation=f"{rule['description']} on line {line_idx}.",
                    suggested_fix=rule["fix"],
                    line_number=line_idx
                ))

    return findings
