import json
import logging
from typing import List, Dict, Any
from openai import AsyncOpenAI

from app.config import settings
from app.services.code_scanner.github_client import GitHubClient
from app.schemas.code_scan import VulnerabilityIssue

logger = logging.getLogger(__name__)

api_key = settings.openai_api_key or "mock-key-for-testing"
client = AsyncOpenAI(api_key=api_key)

class CodeScanOrchestrator:
    def __init__(self, repo_url: str, github_token: str, branch: str = "main"):
        self.repo_url = repo_url
        self.branch = branch
        self.github = GitHubClient(token=github_token)

    async def triage_files(self, all_files: List[str]) -> List[str]:
        """
        Uses the LLM to select which files are most likely to contain security vulnerabilities 
        (e.g., config files, routers, auth logic).
        """
        if not settings.openai_api_key:
            logger.warning("OPENAI_API_KEY is not set. Triaging all files up to a limit.")
            return all_files[:10] # Hard limit for testing

        # To avoid context limit issues, we might want to chunk this, but for now we pass the list
        # We can enforce a soft limit on the string length
        files_str = "\n".join(all_files)
        if len(files_str) > 15000:
            files_str = files_str[:15000] + "\n... (truncated)"

        prompt = (
            "You are a Senior Application Security Engineer. I have a repository with the following files:\n"
            f"{files_str}\n\n"
            "Select the most critical files to review for security vulnerabilities (e.g., SAST, hardcoded secrets, SQLi, Auth bypass). "
            "Return a JSON object with a single key 'critical_files' containing a list of the exact file paths. "
            "Do not select more than 15 files."
        )

        try:
            response = await client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You always respond with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
            )
            content = response.choices[0].message.content
            if content:
                data = json.loads(content)
                return data.get("critical_files", [])
        except Exception as e:
            logger.error(f"Error triaging files: {e}")
            
        return all_files[:10] # Fallback

    async def analyze_files(self, triaged_files: List[str]) -> List[VulnerabilityIssue]:
        """
        Fetches the contents of the triaged files and uses the LLM to find vulnerabilities.
        """
        vulnerabilities = []
        
        if not settings.openai_api_key:
            return []

        # Analyze files sequentially or in batches (sequential to avoid rate limits for now)
        for file_path in triaged_files:
            content = await self.github.get_file_content(self.repo_url, file_path, self.branch)
            if not content:
                continue
                
            # Truncate very large files
            if len(content) > 20000:
                content = content[:20000]

            prompt = (
                f"Review the following code from the file '{file_path}' for security vulnerabilities.\n"
                "Focus on OWASP Top 10: SQLi, XSS, Hardcoded Secrets, IDOR, Misconfigurations, etc.\n\n"
                f"CODE:\n{content}\n\n"
                "Return a JSON object with a key 'vulnerabilities' containing a list of objects. "
                "Each object MUST have the following keys: "
                "'severity' (Critical, High, Medium, Low), "
                "'issue' (A short title), "
                "'explanation' (1-2 sentences explaining the vulnerability), "
                "'suggested_fix' (Code snippet or clear instructions to fix), "
                "'line_number' (integer or null if general)."
            )

            try:
                response = await client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a SAST security agent. Always respond with valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2,
                )
                
                resp_content = response.choices[0].message.content
                if resp_content:
                    data = json.loads(resp_content)
                    vulns = data.get("vulnerabilities", [])
                    for v in vulns:
                        vulnerabilities.append(VulnerabilityIssue(
                            file_path=file_path,
                            severity=v.get("severity", "Medium"),
                            issue=v.get("issue", "Unknown Issue"),
                            explanation=v.get("explanation", ""),
                            suggested_fix=v.get("suggested_fix"),
                            line_number=v.get("line_number")
                        ))
            except Exception as e:
                logger.error(f"Error analyzing file {file_path}: {e}")

        return vulnerabilities

    async def generate_summary(self, vulnerabilities: List[VulnerabilityIssue]) -> str:
        if not vulnerabilities:
            return "No obvious security vulnerabilities found in the scanned files."
            
        if not settings.openai_api_key:
            return f"Found {len(vulnerabilities)} potential issues."

        issues_data = [v.model_dump() for v in vulnerabilities]
        prompt = (
            "You are a Senior AppSec Manager. Summarize the following list of vulnerabilities found in a recent scan. "
            "Provide a 2-3 paragraph executive summary of the repository's security posture. "
            "Keep it professional and highlight the most critical risks.\n\n"
            f"{json.dumps(issues_data)}"
        )

        try:
            response = await client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
            )
            return response.choices[0].message.content or "Could not generate summary."
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            return f"Found {len(vulnerabilities)} potential issues."
