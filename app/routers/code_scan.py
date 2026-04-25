import logging
import uuid
import json
from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from app.schemas.code_scan import CodeScanRequest, CodeScanResponse, CodeChatRequest, CodeChatResponse
from app.services.code_scanner.orchestrator import CodeScanOrchestrator
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["code-scan"])

# In-memory store for scan results to support chat context.
# In a real production app, this would be stored in the database.
scan_store: Dict[str, CodeScanResponse] = {}

@router.post("/code-scan/analyze", response_model=CodeScanResponse)
async def analyze_codebase(request: CodeScanRequest):
    logger.info(f"Starting code scan for {request.repo_url}")
    
    try:
        orchestrator = CodeScanOrchestrator(
            repo_url=request.repo_url,
            github_token=request.github_token,
            branch=request.branch or "main"
        )
        
        # 1. Fetch repo structure
        all_files = await orchestrator.github.get_repo_tree(request.repo_url, request.branch or "main")
        
        # 2. Triage files
        triaged_files = await orchestrator.triage_files(all_files)
        logger.info(f"Triaged {len(triaged_files)} files out of {len(all_files)}.")
        
        # 3. Analyze triaged files
        vulnerabilities = await orchestrator.analyze_files(triaged_files)
        
        # 4. Generate Summary
        summary = await orchestrator.generate_summary(vulnerabilities)
        
        scan_id = str(uuid.uuid4())
        
        response = CodeScanResponse(
            scan_id=scan_id,
            repo_url=request.repo_url,
            summary=summary,
            issues=vulnerabilities
        )
        
        # Save to in-memory store for the chat feature
        scan_store[scan_id] = response
        
        return response
    except Exception as e:
        logger.error(f"Code scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/code-scan/chat", response_model=CodeChatResponse)
async def chat_with_scan(request: CodeChatRequest):
    if not settings.gemini_api_key:
        raise HTTPException(status_code=400, detail="AI Chat is disabled because GEMINI_API_KEY is not configured.")
        
    from google import genai
    with open("/app/models.txt", "w") as f:
        # Just writing a placeholder, list_models is different in new SDK
        f.write("AVAILABLE MODELS: migrated to new SDK")
        
    scan_data = scan_store.get(request.scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan ID not found or expired.")
        
    prompt = (
        "You are SecureLens AI, an expert application security assistant. "
        "You are helping a developer understand a security scan report for their codebase. "
        f"Here is the context of the scan for the repository {scan_data.repo_url}:\n"
        f"Summary: {scan_data.summary}\n"
        f"Vulnerabilities: {json.dumps([v.model_dump() for v in scan_data.issues])}\n\n"
        f"User Message: {request.message}\n\n"
        "Answer the user's questions clearly, concisely, and professionally. Provide code fixes if requested."
    )

    try:
        from google import genai
        from google.genai import types
        
        client = genai.Client(api_key=settings.gemini_api_key)
        response = await client.aio.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.5,
            )
        )
        reply = response.text or "No response from AI."
        return CodeChatResponse(reply=reply)
    except Exception as e:
        logger.error(f"AI Chat Error: {str(e)}")
        raise HTTPException(status_code=500, detail="I encountered an error trying to process your request.")
