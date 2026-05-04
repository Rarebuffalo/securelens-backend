from datetime import datetime
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any

class CodeScanRequest(BaseModel):
    repo_url: str
    github_token: str
    # branch or commit hash optional
    branch: Optional[str] = "main"

class VulnerabilityIssue(BaseModel):
    file_path: str
    severity: str  # High, Medium, Low, Critical
    issue: str
    explanation: str
    suggested_fix: Optional[str] = None
    line_number: Optional[int] = None

class CodeScanResponse(BaseModel):
    scan_id: str
    repo_url: str
    summary: str
    issues: List[VulnerabilityIssue]
    created_at: Optional[datetime] = None

class CodeChatRequest(BaseModel):
    scan_id: str
    message: str

class CodeChatResponse(BaseModel):
    reply: str

class CodeScanHistoryItem(BaseModel):
    id: str
    repo_url: str
    created_at: datetime

    model_config = {"from_attributes": True}

class CodeScanHistoryResponse(BaseModel):
    scans: List[CodeScanHistoryItem]
    total: int
    page: int
    per_page: int
