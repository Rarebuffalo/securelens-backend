"""
Code Scan Router
================

Two endpoints:
  POST /code-scan/analyze  — Clone repo tree, triage + analyze files with AI,
                              persist result to PostgreSQL, return scan_id.
  POST /code-scan/chat     — Load the persisted scan from DB and answer questions.
  GET  /code-scan/history  — List your past repository scans.
  GET  /code-scan/{id}     — Get details of a specific code scan.
  DELETE /code-scan/{id}  — Delete a code scan.
  GET  /code-scan/models   — List available AI models (debug / informational).

Why we moved away from in-memory scan_store:
  The original implementation stored scan results in a plain Python dict.
  This caused two critical problems:
    1. Any server restart or crash wiped all stored context, breaking chat.
    2. Multiple Uvicorn workers have isolated memory; a scan on worker A
       cannot be chatted with on worker B.
  By persisting to PostgreSQL we get durability, scalability, and historical
  records of all code scans (same pattern as the web scanner).
"""

import logging
import json
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict

from app.database import get_db
from app.middleware.auth import get_current_user, get_optional_user
from app.models.code_scan import CodeScanResult
from app.models.user import User
from app.schemas.code_scan import (
    CodeScanRequest,
    CodeScanResponse,
    CodeChatRequest,
    CodeChatResponse,
    VulnerabilityIssue,
    CodeScanHistoryItem,
    CodeScanHistoryResponse,
)
from app.services.code_scanner.orchestrator import CodeScanOrchestrator
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["code-scan"])


# ---------------------------------------------------------------------------
# POST /code-scan/analyze
# ---------------------------------------------------------------------------

@router.post("/code-scan/analyze", response_model=CodeScanResponse)
async def analyze_codebase(
    request: CodeScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    """
    Full agentic scan of a GitHub repository.

    Flow:
      1. Fetch the full file tree from GitHub.
      2. Ask the AI to triage (select) the most security-critical files.
      3. Analyze each triaged file for OWASP Top-10 vulnerabilities.
      4. Generate an executive summary of all findings.
      5. Persist the result to `code_scan_results` table.
      6. Return the scan_id so the frontend can open a chat session.
    """
    logger.info(f"Starting code scan for {request.repo_url}")

    try:
        orchestrator = CodeScanOrchestrator(
            repo_url=request.repo_url,
            github_token=request.github_token,
            branch=request.branch or "main",
        )

        # Step 1 — Fetch file tree
        all_files = await orchestrator.github.get_repo_tree(
            request.repo_url, request.branch or "main"
        )

        # Step 2 — AI triage: pick the most security-sensitive files
        triaged_files = await orchestrator.triage_files(all_files)
        logger.info(f"Triaged {len(triaged_files)} files out of {len(all_files)}.")

        # Step 3 — Analyze each file
        vulnerabilities = await orchestrator.analyze_files(triaged_files)

        # Step 4 — Generate summary
        summary = await orchestrator.generate_summary(vulnerabilities)

        # Step 5 — Persist to database
        # Serialise VulnerabilityIssue objects to plain dicts for JSON storage.
        issues_as_dicts = [v.model_dump() for v in vulnerabilities]

        scan_record = CodeScanResult(
            user_id=current_user.id if current_user else None,
            repo_url=request.repo_url,
            summary=summary,
            issues=issues_as_dicts,
        )
        db.add(scan_record)
        await db.flush()  # flush to get the auto-generated id without committing yet
        scan_id = scan_record.id

        logger.info(f"Code scan {scan_id} persisted to database.")

        return CodeScanResponse(
            scan_id=scan_id,
            repo_url=request.repo_url,
            summary=summary,
            issues=vulnerabilities,
        )

    except Exception as e:
        logger.error(f"Code scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# POST /code-scan/chat
# ---------------------------------------------------------------------------

@router.post("/code-scan/chat", response_model=CodeChatResponse)
async def chat_with_scan(
    request: CodeChatRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Conversational Q&A grounded in a previously completed code scan.

    We load the scan from PostgreSQL using the scan_id, so this works
    correctly across server restarts and multiple workers.
    """
    if not settings.ai_api_key:
        raise HTTPException(
            status_code=400,
            detail="AI Chat is disabled because no AI API key is configured.",
        )

    # Load the scan record from DB
    result = await db.execute(
        select(CodeScanResult).where(CodeScanResult.id == request.scan_id)
    )
    scan_data = result.scalar_one_or_none()

    if not scan_data:
        raise HTTPException(
            status_code=404,
            detail="Scan ID not found. The scan may have expired or never existed.",
        )

    # Build a rich context-aware prompt
    prompt = (
        "You are SecureLens AI, an expert application security assistant. "
        "You are helping a developer understand a security scan report for their codebase. "
        f"Here is the context of the scan for the repository '{scan_data.repo_url}':\n\n"
        f"Executive Summary:\n{scan_data.summary}\n\n"
        f"Vulnerabilities Found:\n{json.dumps(scan_data.issues, indent=2)}\n\n"
        f"Developer's Question: {request.message}\n\n"
        "Answer clearly, concisely, and professionally. "
        "Provide specific code fixes when requested. "
        "Reference the exact file paths and line numbers from the scan data when relevant."
    )

    try:
        # Use the unified AI service so it respects whatever provider is configured
        from app.services.ai import call_ai
        reply = await call_ai(prompt, temperature=0.5)
        return CodeChatResponse(reply=reply)
    except Exception as e:
        logger.error(f"AI Chat Error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="I encountered an error trying to process your request.",
        )


# ---------------------------------------------------------------------------
# History Management
# ---------------------------------------------------------------------------

@router.get("/code-scan/history", response_model=CodeScanHistoryResponse)
async def list_code_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List history of repository scans for the authenticated user.
    """
    offset = (page - 1) * per_page

    # Count total scans for this user
    count_result = await db.execute(
        select(func.count()).select_from(CodeScanResult).where(CodeScanResult.user_id == current_user.id)
    )
    total = count_result.scalar_one()

    # Fetch paginated results
    result = await db.execute(
        select(CodeScanResult)
        .where(CodeScanResult.user_id == current_user.id)
        .order_by(CodeScanResult.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    scans = result.scalars().all()

    return CodeScanHistoryResponse(
        scans=[CodeScanHistoryItem.model_validate(s) for s in scans],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/code-scan/{scan_id}", response_model=CodeScanResponse)
async def get_code_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Fetch the full details of a specific code scan by ID.
    """
    result = await db.execute(
        select(CodeScanResult).where(
            CodeScanResult.id == scan_id,
            CodeScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    return CodeScanResponse(
        scan_id=scan.id,
        repo_url=scan.repo_url,
        summary=scan.summary,
        issues=[VulnerabilityIssue(**i) for i in scan.issues],
        created_at=scan.created_at,
    )


@router.delete("/code-scan/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_code_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a code scan record from history.
    """
    result = await db.execute(
        select(CodeScanResult).where(
            CodeScanResult.id == scan_id,
            CodeScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    await db.delete(scan)
    await db.commit()


# ---------------------------------------------------------------------------
# GET /code-scan/models  (informational / debug)
# ---------------------------------------------------------------------------

@router.get("/code-scan/models")
async def list_available_models():
    """
    Lists AI models available to the configured provider.
    Only meaningful when using the Gemini provider.
    """
    if not settings.ai_api_key:
        raise HTTPException(status_code=500, detail="No AI API key is set.")
    try:
        from google import genai

        client = genai.Client(api_key=settings.ai_api_key)
        models = []
        for model in client.models.list():
            if "generateContent" in model.supported_actions:
                models.append(model.name)
        return {"models": models}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching models: {e}")
