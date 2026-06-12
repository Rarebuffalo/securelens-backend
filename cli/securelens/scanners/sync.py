import os
import httpx
from typing import Optional
from securelens.scanners import LocalScanResult

BACKEND_URL_DEFAULT = "http://localhost:8000"

async def sync_scan_to_backend(result: LocalScanResult, token: Optional[str] = None) -> Optional[str]:
    """
    Synchronizes a LocalScanResult with the SecureLens central backend.
    
    Parameters
    ----------
    result : The LocalScanResult instance containing findings.
    token  : Optional JWT Bearer token to associate the scan with a user account.
    
    Returns
    -------
    The assigned scan_id from the database on success, or None on failure.
    """
    backend_base = os.environ.get("SECURELENS_BACKEND_URL") or BACKEND_URL_DEFAULT
    sync_url = f"{backend_base.rstrip('/')}/code-scan/sync"

    # Construct the payload matching the CodeScanSyncRequest schema
    payload = {
        "repo_url": result.target,
        "summary": result.ai_summary or f"Local scan completed with {len(result.vulnerabilities)} issue(s).",
        "issues": [
            {
                "file_path": v.file_path,
                "severity": v.severity,
                "issue": v.issue,
                "explanation": v.explanation,
                "suggested_fix": v.suggested_fix or "",
                "line_number": v.line_number
            }
            for v in result.vulnerabilities
        ]
    }

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif os.environ.get("SECURELENS_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ.get('SECURELENS_TOKEN')}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(sync_url, json=payload, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data.get("scan_id")
            else:
                # Fallback check for alternative key structures
                response_data = response.json()
                if "scan_id" in response_data:
                    return response_data["scan_id"]
                return None
    except Exception as e:
        # Silently fail sync, but return None so caller can notify user
        return None
