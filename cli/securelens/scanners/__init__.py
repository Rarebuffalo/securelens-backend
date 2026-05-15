"""
Local Code Scanner
==================
Scans a local directory — no GitHub API needed.

Pipeline:
  1. Walk the filesystem, respecting .gitignore rules and config ignore patterns
  2. Flag files matching known sensitive patterns (always include these)
  3. Send the file list to the AI for triage (pick the most security-critical ones)
  4. Read each triaged file and send to AI for OWASP vulnerability analysis
  5. Return structured list of vulnerability findings
"""

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pathspec

from securelens.ai import call_ai, call_ai_json
from securelens.ai.prompts import triage_prompt, analysis_prompt
from securelens.config import CLIConfig

logger = logging.getLogger(__name__)

# ── File extension blocklist (binary / generated — no security signal) ────────
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".whl", ".egg", ".jar", ".war", ".ear",
    ".mp4", ".mp3", ".avi", ".mov",
    ".ttf", ".woff", ".woff2", ".eot",
    ".pyc", ".pyo", ".class",
    ".so", ".dll", ".dylib", ".exe",
    ".db", ".sqlite", ".sqlite3",
}

# ── Files that are always included regardless of AI triage ───────────────────
ALWAYS_SCAN_PATTERNS = [
    "*.env", ".env", ".env.*", "*.env.*",
    "config.py", "settings.py", "config.js", "config.ts",
    "secrets.py", "credentials.py", "keys.py",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "*.pem", "*.key", "*.p12", "*.pfx",
    "requirements.txt", "package.json", "Gemfile",
]

SENSITIVE_NAME_KEYWORDS = [
    "secret", "password", "passwd", "credential", "cred",
    "api_key", "apikey", "auth", "jwt", "token",
    "private", "priv_key", "access_key",
]


@dataclass
class VulnerabilityFinding:
    file_path: str
    severity: str          # Critical | High | Medium | Low
    issue: str
    explanation: str
    suggested_fix: str
    line_number: Optional[int] = None


@dataclass
class LocalScanResult:
    target: str
    total_files_found: int
    files_triaged: list[str] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    ai_summary: str = ""
    score: int = 100
    grade: str = "A"

    def compute_score(self) -> None:
        """Deterministic score: deduct points by severity."""
        weights = {"Critical": 20, "High": 12, "Medium": 5, "Low": 2}
        deduction = sum(weights.get(v.severity, 0) for v in self.vulnerabilities)
        self.score = max(100 - deduction, 0)
        self.grade = _score_to_grade(self.score)


def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


# ── Phase 1: File Discovery ───────────────────────────────────────────────────

def discover_files(root: Path, cfg: CLIConfig) -> list[Path]:
    """
    Walk the directory tree and return candidate files.
    Respects .gitignore in the root and cfg.ignore_patterns.
    Skips binaries and files larger than cfg.max_file_size_kb.
    """
    # Build a combined spec from config ignore_patterns + .gitignore
    ignore_patterns = list(cfg.ignore_patterns)
    gitignore_path = root / ".gitignore"
    if gitignore_path.exists():
        with open(gitignore_path) as f:
            ignore_patterns.extend(
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            )

    spec = pathspec.PathSpec.from_lines("gitwildmatch", ignore_patterns)
    max_bytes = cfg.max_file_size_kb * 1024

    candidates: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if spec.match_file(rel):
            continue
        if p.suffix.lower() in BINARY_EXTENSIONS:
            continue
        if p.stat().st_size > max_bytes:
            continue
        candidates.append(p)

    return sorted(candidates)


def _is_always_scan(path: Path) -> bool:
    """Returns True if this file should always be scanned regardless of triage."""
    name = path.name.lower()
    # Check sensitive name keywords
    if any(kw in name for kw in SENSITIVE_NAME_KEYWORDS):
        return True
    # Check always-scan patterns
    for pattern in ALWAYS_SCAN_PATTERNS:
        if path.match(pattern):
            return True
    return False


# ── Phase 2: AI Triage ───────────────────────────────────────────────────────

async def triage_files(
    candidates: list[Path],
    root: Path,
    cfg: CLIConfig,
) -> list[Path]:
    """
    Ask the AI to pick the most security-relevant files.
    Always-scan files are added automatically regardless of AI choice.
    """
    # Separate forced files from candidates
    forced = [p for p in candidates if _is_always_scan(p)]
    non_forced = [p for p in candidates if not _is_always_scan(p)]

    # Build file list for AI (relative paths — cleaner prompt)
    rel_paths = [p.relative_to(root).as_posix() for p in non_forced]
    remaining_budget = max(0, cfg.max_files_to_scan - len(forced))

    ai_selected: list[Path] = []
    if rel_paths and remaining_budget > 0 and cfg.api_key:
        file_list_str = "\n".join(rel_paths[:300])  # cap to ~300 paths for token budget
        prompt = triage_prompt(file_list_str, remaining_budget)
        result = await call_ai_json(prompt, cfg.api_key, cfg.default_model, temperature=0.1)
        if result and "critical_files" in result:
            for rel in result["critical_files"]:
                abs_path = root / rel
                if abs_path.exists():
                    ai_selected.append(abs_path)

    # Merge: forced first, then AI-selected (deduplicated)
    seen = set()
    final: list[Path] = []
    for p in forced + ai_selected:
        if p not in seen:
            seen.add(p)
            final.append(p)

    return final[:cfg.max_files_to_scan]


# ── Phase 3: File Analysis ────────────────────────────────────────────────────

async def analyze_file(
    path: Path,
    root: Path,
    cfg: CLIConfig,
) -> list[VulnerabilityFinding]:
    """Send a single file's content to the AI for OWASP analysis."""
    rel = path.relative_to(root).as_posix()
    try:
        content = path.read_text(errors="replace")
    except Exception as e:
        logger.warning(f"Could not read {rel}: {e}")
        return []

    # Cap content to avoid token overflow
    if len(content) > 30_000:
        content = content[:30_000] + "\n... (truncated)"

    prompt = analysis_prompt(rel, content)
    result = await call_ai_json(prompt, cfg.api_key, cfg.default_model, temperature=0.2)
    if not result:
        return []

    findings: list[VulnerabilityFinding] = []
    for v in result.get("vulnerabilities", []):
        findings.append(VulnerabilityFinding(
            file_path=rel,
            severity=v.get("severity", "Medium"),
            issue=v.get("issue", "Unknown Issue"),
            explanation=v.get("explanation", ""),
            suggested_fix=v.get("suggested_fix", ""),
            line_number=v.get("line_number"),
        ))
    return findings


async def analyze_files(
    triaged: list[Path],
    root: Path,
    cfg: CLIConfig,
    progress_callback=None,
) -> list[VulnerabilityFinding]:
    """
    Analyze all triaged files concurrently.
    Uses a semaphore to avoid hammering the API with too many simultaneous calls.
    """
    semaphore = asyncio.Semaphore(4)
    all_findings: list[VulnerabilityFinding] = []

    async def _analyze_with_sem(path: Path, idx: int) -> list[VulnerabilityFinding]:
        async with semaphore:
            result = await analyze_file(path, root, cfg)
            if progress_callback:
                await progress_callback(idx + 1, len(triaged), path.relative_to(root).as_posix())
            return result

    tasks = [_analyze_with_sem(p, i) for i, p in enumerate(triaged)]
    results = await asyncio.gather(*tasks)
    for r in results:
        all_findings.extend(r)

    return all_findings
