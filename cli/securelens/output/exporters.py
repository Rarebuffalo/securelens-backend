"""
Export Formatters
=================
Serializes scan results to JSON and Markdown.
"""

import json
from datetime import datetime
from pathlib import Path


# ── JSON ──────────────────────────────────────────────────────────────────────

def to_json(result, target_type: str = "code") -> str:
    """Serialize a scan result to a JSON string."""
    if target_type == "code":
        data = {
            "scan_type": "code",
            "target": result.target,
            "timestamp": datetime.now().isoformat(),
            "score": result.score,
            "grade": result.grade,
            "files_scanned": result.files_triaged,
            "total_issues": len(result.vulnerabilities),
            "vulnerabilities": [
                {
                    "file": v.file_path,
                    "line": v.line_number,
                    "severity": v.severity,
                    "issue": v.issue,
                    "explanation": v.explanation,
                    "fix": v.suggested_fix,
                }
                for v in result.vulnerabilities
            ],
            "ai_summary": result.ai_summary,
        }
    else:  # web
        data = {
            "scan_type": "web",
            "target": result.url,
            "timestamp": datetime.now().isoformat(),
            "score": result.score,
            "grade": result.grade,
            "ssl_expiry_days": result.ssl_expiry_days,
            "exposed_paths": result.exposed_paths,
            "total_issues": len(result.issues),
            "issues": [
                {
                    "layer": i.layer,
                    "severity": i.severity,
                    "issue": i.issue,
                    "fix": i.fix,
                }
                for i in result.issues
            ],
            "ai_summary": result.ai_summary,
        }
    return json.dumps(data, indent=2)


def save_json(result, target_type: str = "code") -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(f"securelens-report-{ts}.json")
    path.write_text(to_json(result, target_type))
    return path


# ── Markdown ──────────────────────────────────────────────────────────────────

def to_markdown(result, target_type: str = "code") -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    if target_type == "code":
        lines.append(f"# SecureLens AI — Code Security Report\n")
        lines.append(f"**Target:** `{result.target}`  ")
        lines.append(f"**Score:** {result.score}/100  **Grade:** {result.grade}  ")
        lines.append(f"**Files Scanned:** {len(result.files_triaged)}  ")
        lines.append(f"**Issues Found:** {len(result.vulnerabilities)}  ")
        lines.append(f"**Generated:** {ts}\n")

        if result.ai_summary:
            lines.append("## AI Summary\n")
            lines.append(result.ai_summary)
            lines.append("\n")

        severity_order = ["Critical", "High", "Medium", "Low"]
        grouped: dict = {s: [] for s in severity_order}
        for v in result.vulnerabilities:
            sev = v.severity if v.severity in grouped else "Low"
            grouped[sev].append(v)

        for sev in severity_order:
            items = grouped[sev]
            if not items:
                continue
            lines.append(f"## {sev} ({len(items)})\n")
            for v in items:
                loc = v.file_path
                if v.line_number:
                    loc += f":{v.line_number}"
                lines.append(f"### `{v.issue}`")
                lines.append(f"**File:** `{loc}`  ")
                lines.append(f"**Risk:** {v.explanation}  ")
                lines.append(f"**Fix:** {v.suggested_fix}\n")

        lines.append("## Files Scanned\n")
        for f in result.files_triaged:
            lines.append(f"- `{f}`")

    else:  # web
        lines.append(f"# SecureLens AI — Web Security Report\n")
        lines.append(f"**Target:** {result.url}  ")
        lines.append(f"**Score:** {result.score}/100  **Grade:** {result.grade}  ")
        lines.append(f"**Issues Found:** {len(result.issues)}  ")
        if result.ssl_expiry_days is not None:
            lines.append(f"**SSL Expires In:** {result.ssl_expiry_days} days  ")
        lines.append(f"**Generated:** {ts}\n")

        if result.ai_summary:
            lines.append("## AI Summary\n")
            lines.append(result.ai_summary)
            lines.append("\n")

        if result.exposed_paths:
            lines.append("## Exposed Paths\n")
            for p in result.exposed_paths:
                lines.append(f"- `{p}`")
            lines.append("")

        layers: dict = {}
        for issue in result.issues:
            layers.setdefault(issue.layer, []).append(issue)
        for layer, items in layers.items():
            lines.append(f"## {layer}\n")
            for item in items:
                lines.append(f"**[{item.severity}]** {item.issue}  ")
                lines.append(f"*Fix:* {item.fix}\n")

    return "\n".join(lines)


def save_markdown(result, target_type: str = "code") -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(f"securelens-report-{ts}.md")
    path.write_text(to_markdown(result, target_type))
    return path
