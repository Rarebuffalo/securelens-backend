from datetime import datetime

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(..., description="The URL of the website to scan")


class Issue(BaseModel):
    issue: str
    severity: str
    layer: str
    fix: str
    contextual_severity: str | None = None
    explanation: str | None = None
    remediation_snippet: str | None = None


class LayerStatus(BaseModel):
    issues: int = 0
    status: str = "green"


class ScanResponse(BaseModel):
    id: str | None = None
    url: str
    security_score: int
    layers: dict[str, LayerStatus]
    issues: list[Issue]
    created_at: datetime | None = None


class ScanHistoryItem(BaseModel):
    id: str
    url: str
    security_score: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    scans: list[ScanHistoryItem]
    total: int
    page: int
    per_page: int


class DashboardTrendsResponse(BaseModel):
    total_scans: int
    average_score: float
    recent_scans: list[ScanHistoryItem]


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str


class ThreatNarrativeResponse(BaseModel):
    narrative: str


class ScanDiffResponse(BaseModel):
    resolved_issues: list[Issue]
    new_issues: list[Issue]
    persisting_issues: list[Issue]
    score_change: int
