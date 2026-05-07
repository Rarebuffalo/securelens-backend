"""
Nuclei Scanner
==============

Wraps the Nuclei CLI tool (https://github.com/projectdiscovery/nuclei) as an
async subprocess call so it can run as a background task after the main scan
response has been returned to the client.

Why a background task?
  Nuclei is an active scanner — it actually sends probe requests to the target.
  A typical run takes 30–120 seconds, which is far too slow to block an API
  response. Running it in the background lets the client get the passive scan
  results immediately, and then poll GET /scans/{id}/nuclei for the Nuclei
  findings when they are ready.

Nuclei is completely optional. If the binary is not found in PATH (or the
configured path), the scan is silently skipped and the NucleiScanResult row
is saved with status "skipped". No error is raised.

Output format:
  Nuclei outputs one JSON object per line (-json flag). Each line looks like:
  {
    "template-id": "...",
    "info": {"name": "...", "severity": "..."},
    "matched-at": "https://...",
    "description": "..."
  }

Installation:
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  Or download the binary from https://github.com/projectdiscovery/nuclei/releases
"""

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.nuclei_result import NucleiScanResult

logger = logging.getLogger(__name__)

# Conservative timeout — Nuclei can be slow, but we cap it at 90 seconds
# to prevent background tasks from running indefinitely.
NUCLEI_TIMEOUT_SECONDS = 90


def _find_nuclei_binary() -> str | None:
    """
    Resolve the Nuclei binary path.

    Checks the configured path first (NUCLEI_BINARY_PATH env var), then
    falls back to searching PATH. Returns None if not found anywhere.
    """
    if settings.nuclei_binary_path:
        return settings.nuclei_binary_path

    return shutil.which("nuclei")


def _parse_nuclei_output(stdout: bytes) -> list[dict]:
    """
    Parse Nuclei's JSONL output into a list of finding dicts.

    Each line of stdout is expected to be a valid JSON object. Lines that
    fail to parse are skipped with a warning.
    """
    findings = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
            # Normalise into a flat schema we control
            findings.append({
                "template_id": raw.get("template-id", "unknown"),
                "name": raw.get("info", {}).get("name", "Unknown"),
                "severity": raw.get("info", {}).get("severity", "info"),
                "matched_at": raw.get("matched-at", ""),
                "description": raw.get("info", {}).get("description", None),
            })
        except json.JSONDecodeError:
            logger.warning(f"Nuclei: could not parse output line: {line[:200]}")

    return findings


async def run_nuclei_scan(scan_result_id: str, url: str) -> None:
    """
    Entry point for the background Nuclei scan task.

    This runs after the main scan response has been sent. It:
      1. Checks if the Nuclei binary is available
      2. Runs Nuclei against the URL with a timeout
      3. Parses the JSONL output
      4. Saves a NucleiScanResult row to the database

    The NucleiScanResult.status field reflects the outcome:
      - "completed" : Nuclei ran and (possibly) found issues
      - "skipped"   : Nuclei binary not found
      - "timeout"   : Nuclei ran but exceeded the timeout
      - "error"     : Nuclei subprocess failed
    """
    nuclei_path = _find_nuclei_binary()

    if not nuclei_path:
        logger.info(
            "Nuclei binary not found — active scan skipped. "
            "Install nuclei and set NUCLEI_BINARY_PATH if you want active scanning."
        )
        await _save_nuclei_result(scan_result_id, url, [], "skipped")
        return

    logger.info(f"Nuclei active scan starting: {url}")

    try:
        proc = await asyncio.create_subprocess_exec(
            nuclei_path,
            "-u", url,
            "-json",          # output as JSON lines
            "-silent",        # suppress banner/progress
            "-timeout", "10", # per-request timeout in seconds (inside Nuclei)
            "-rate-limit", "10",  # be polite — 10 req/s max
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=NUCLEI_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning(f"Nuclei timed out after {NUCLEI_TIMEOUT_SECONDS}s for {url}")
            await _save_nuclei_result(scan_result_id, url, [], "timeout")
            return

        if proc.returncode not in (0, 1):
            # Nuclei exits 1 when it finds nothing — that's not an error
            err = stderr.decode("utf-8", errors="replace")[:500]
            logger.error(f"Nuclei exited with code {proc.returncode}: {err}")
            await _save_nuclei_result(scan_result_id, url, [], "error")
            return

        findings = _parse_nuclei_output(stdout)
        logger.info(f"Nuclei scan complete: {url} — {len(findings)} finding(s)")
        await _save_nuclei_result(scan_result_id, url, findings, "completed")

    except FileNotFoundError:
        logger.error(f"Nuclei binary not executable at path: {nuclei_path}")
        await _save_nuclei_result(scan_result_id, url, [], "skipped")
    except Exception as e:
        logger.error(f"Nuclei scan failed for {url}: {e}", exc_info=True)
        await _save_nuclei_result(scan_result_id, url, [], "error")


async def _save_nuclei_result(
    scan_result_id: str,
    url: str,
    findings: list[dict],
    status: str,
) -> None:
    """Persist the Nuclei scan result. Uses its own session (background context)."""
    async with AsyncSessionLocal() as db:
        row = NucleiScanResult(
            scan_result_id=scan_result_id,
            url=url,
            findings=findings,
            status=status,
            completed_at=datetime.now(timezone.utc),
        )
        db.add(row)
        await db.commit()
