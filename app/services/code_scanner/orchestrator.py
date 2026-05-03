"""
Code Scan Orchestrator
=======================

Coordinates the three phases of an agentic code security scan:
  1. Triage   — Ask the AI which files are worth scanning.
  2. Analyze  — Send each file's code to the AI for OWASP vulnerability review.
  3. Summarize— Generate an executive summary of all findings.

Previously this used the google-genai SDK directly. It now delegates all AI
calls to app.services.ai.call_ai(), which is provider-agnostic via LiteLLM.
This means switching from Gemini to Claude (or any other model) automatically
applies to the code scanner without any changes here.
"""

import json
import logging
import asyncio
from typing import List

from app.config import settings
from app.services.ai import call_ai
from app.services.code_scanner.github_client import GitHubClient
from app.schemas.code_scan import VulnerabilityIssue

logger = logging.getLogger(__name__)


class CodeScanOrchestrator:
    def __init__(self, repo_url: str, github_token: str, branch: str = "main"):
        self.repo_url = repo_url
        self.branch = branch
        self.github = GitHubClient(token=github_token)

    async def triage_files(self, all_files: List[str]) -> List[str]:
        """
        Phase 1 — AI-driven file triage.

        Sends the full file tree to the LLM and asks it to select the
        most security-critical files (e.g. auth handlers, DB queries,
        config files). Caps at 5 files to stay within token budgets.

        Falls back to the first 5 files if the AI call fails or no key
        is configured.
        """
        if not settings.effective_ai_key:
            logger.warning("No AI key set. Falling back to first 5 files.")
            return all_files[:5]

        files_str = "\n".join(all_files)
        if len(files_str) > 15000:
            files_str = files_str[:15000] + "\n... (truncated)"

        prompt = (
            "You are a Senior Application Security Engineer. I have a repository with the following files:\n"
            f"{files_str}\n\n"
            "Select the most critical files to review for security vulnerabilities "
            "(e.g. authentication, database access, config, API routes, secrets handling). "
            "Return a JSON object with a single key 'critical_files' containing a list of "
            "the exact file paths from the list above. Do not select more than 5 files."
        )

        try:
            raw = await call_ai(prompt, temperature=0.1, json_mode=True)
            if raw:
                data = json.loads(raw)
                return data.get("critical_files", [])
        except Exception as e:
            logger.error(f"File triage failed: {e}")

        return all_files[:5]

    async def analyze_files(self, triaged_files: List[str]) -> List[VulnerabilityIssue]:
        """
        Phase 2 — Per-file SAST analysis.

        Downloads each file's source code from GitHub and sends it to
        the AI for a focused OWASP Top-10 vulnerability review.

        Concurrency is throttled with a semaphore to avoid hitting
        provider rate limits (max 5 simultaneous AI requests).
        """
        if not settings.effective_ai_key:
            return []

        vulnerabilities = []
        # Limit concurrent AI calls to avoid rate-limiting
        semaphore = asyncio.Semaphore(5)

        async def process_file(file_path: str) -> List[VulnerabilityIssue]:
            # Skip lock files — huge, slow, zero security signal
            if file_path.endswith(("package-lock.json", "yarn.lock", "poetry.lock")):
                return []

            content = await self.github.get_file_content(
                self.repo_url, file_path, self.branch
            )
            if not content:
                return []

            # Cap file size to avoid token overflows
            if len(content) > 30000:
                content = content[:30000]

            prompt = (
                f"Review the following code from '{file_path}' for security vulnerabilities.\n"
                "Focus on OWASP Top 10: SQL Injection, XSS, Hardcoded Secrets, IDOR, "
                "Insecure Deserialization, Broken Auth, Misconfigurations, SSRF, etc.\n\n"
                f"CODE:\n{content}\n\n"
                "Return a JSON object with a key 'vulnerabilities' containing a list of objects. "
                "Each object MUST have the following keys:\n"
                "  'severity'     : Critical | High | Medium | Low\n"
                "  'issue'        : Short title of the vulnerability\n"
                "  'explanation'  : 1-2 sentences explaining the risk\n"
                "  'suggested_fix': Code snippet or clear instruction to fix it\n"
                "  'line_number'  : Integer line number, or null if not applicable\n"
                "If no vulnerabilities are found, return {\"vulnerabilities\": []}."
            )

            file_vulns = []
            async with semaphore:
                try:
                    raw = await call_ai(prompt, temperature=0.2, json_mode=True)
                    if raw:
                        data = json.loads(raw)
                        for v in data.get("vulnerabilities", []):
                            file_vulns.append(
                                VulnerabilityIssue(
                                    file_path=file_path,
                                    severity=v.get("severity", "Medium"),
                                    issue=v.get("issue", "Unknown Issue"),
                                    explanation=v.get("explanation", ""),
                                    suggested_fix=v.get("suggested_fix"),
                                    line_number=v.get("line_number"),
                                )
                            )
                except Exception as e:
                    logger.error(f"Analysis failed for {file_path}: {e}")

            return file_vulns

        results = await asyncio.gather(*(process_file(f) for f in triaged_files))
        for res in results:
            vulnerabilities.extend(res)

        return vulnerabilities

    async def generate_summary(self, vulnerabilities: List[VulnerabilityIssue]) -> str:
        """
        Phase 3 — Executive summary.

        Asks the AI to distill all findings into a 2-3 paragraph summary
        suitable for a security report or management briefing.
        """
        if not vulnerabilities:
            return "No security vulnerabilities were identified in the scanned files."

        if not settings.effective_ai_key:
            return f"Found {len(vulnerabilities)} potential issue(s) across the scanned files."

        issues_data = [v.model_dump() for v in vulnerabilities]
        prompt = (
            "You are a Senior AppSec Manager. Summarize the following list of vulnerabilities "
            "found in a recent automated security scan. Provide a 2-3 paragraph executive summary "
            "of the repository's overall security posture. Highlight the most critical risks "
            "and recommend the immediate priorities. Keep it professional and actionable.\n\n"
            f"Findings:\n{json.dumps(issues_data, indent=2)}"
        )

        result = await call_ai(prompt, temperature=0.4)
        return result or f"Found {len(vulnerabilities)} potential issue(s)."
