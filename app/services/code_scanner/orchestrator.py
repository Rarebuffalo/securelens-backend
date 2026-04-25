import json
import logging
from typing import List, Dict, Any
from google import genai
from google.genai import types
import asyncio

from app.config import settings
from app.services.code_scanner.github_client import GitHubClient
from app.schemas.code_scan import VulnerabilityIssue

logger = logging.getLogger(__name__)

if settings.gemini_api_key:
    # google-genai client init
    ai_client = genai.Client(api_key=settings.gemini_api_key)
else:
    ai_client = None

class CodeScanOrchestrator:
    def __init__(self, repo_url: str, github_token: str, branch: str = "main"):
        self.repo_url = repo_url
        self.branch = branch
        self.github = GitHubClient(token=github_token)
        # We use gemini-2.0-flash for high rate limits and stability
        self.model_name = 'gemini-2.0-flash'

    async def triage_files(self, all_files: List[str]) -> List[str]:
        """
        Uses the LLM to select which files are most likely to contain security vulnerabilities 
        """
        if not settings.gemini_api_key:
            logger.warning("GEMINI_API_KEY is not set. Triaging all files up to a limit.")
            return all_files[:5]

        files_str = "\n".join(all_files)
        if len(files_str) > 15000:
            files_str = files_str[:15000] + "\n... (truncated)"

        prompt = (
            "You are a Senior Application Security Engineer. I have a repository with the following files:\n"
            f"{files_str}\n\n"
            "Select the most critical files to review for security vulnerabilities (e.g., SAST, hardcoded secrets, SQLi, Auth bypass). "
            "Return a JSON object with a single key 'critical_files' containing a list of the exact file paths. "
            "Do not select more than 5 files."
        )

        try:
            response = await ai_client.aio.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1,
                )
            )
            if response.text:
                data = json.loads(response.text)
                return data.get("critical_files", [])
        except Exception as e:
            logger.error(f"Error triaging files: {e}")
            
        return all_files[:5]

    async def analyze_files(self, triaged_files: List[str]) -> List[VulnerabilityIssue]:
        if not settings.gemini_api_key:
            return []

        vulnerabilities = []
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent requests to avoid rate limits
        
        async def process_file(file_path: str):
            # Skip massive dependency lock files as they are too slow and unhelpful for SAST
            if file_path.endswith('package-lock.json') or file_path.endswith('yarn.lock'):
                return []
                
            content = await self.github.get_file_content(self.repo_url, file_path, self.branch)
            if not content:
                return []
                
            if len(content) > 30000:
                content = content[:30000]

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

            file_vulns = []
            async with semaphore:
                try:
                    response = await ai_client.aio.models.generate_content(
                        model=self.model_name,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            temperature=0.2,
                        )
                    )
                    if response.text:
                        data = json.loads(response.text)
                        vulns = data.get("vulnerabilities", [])
                        for v in vulns:
                            file_vulns.append(VulnerabilityIssue(
                                file_path=file_path,
                                severity=v.get("severity", "Medium"),
                                issue=v.get("issue", "Unknown Issue"),
                                explanation=v.get("explanation", ""),
                                suggested_fix=v.get("suggested_fix"),
                                line_number=v.get("line_number")
                            ))
                except Exception as e:
                    logger.error(f"Error analyzing file {file_path}: {e}")
            return file_vulns

        results = await asyncio.gather(*(process_file(f) for f in triaged_files))
        for res in results:
            vulnerabilities.extend(res)
            
        return vulnerabilities

    async def generate_summary(self, vulnerabilities: List[VulnerabilityIssue]) -> str:
        if not vulnerabilities:
            return "No obvious security vulnerabilities found in the scanned files."
            
        if not settings.gemini_api_key:
            return f"Found {len(vulnerabilities)} potential issues."

        issues_data = [v.model_dump() for v in vulnerabilities]
        prompt = (
            "You are a Senior AppSec Manager. Summarize the following list of vulnerabilities found in a recent scan. "
            "Provide a 2-3 paragraph executive summary of the repository's security posture. "
            "Keep it professional and highlight the most critical risks.\n\n"
            f"{json.dumps(issues_data)}"
        )

        try:
            response = await ai_client.aio.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.4,
                )
            )
            return response.text or "Could not generate summary."
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            return f"Found {len(vulnerabilities)} potential issues."
