from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

# Import the ThreatIntelReport schema from the service layer.
# We import it here for use in ScanResponse so the schema stays clean.
from app.services.threat_intel import ThreatIntelReport


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
    # Step 3: Threat intelligence enrichment (optional — only present when API keys are set)
    threat_intel: Optional[ThreatIntelReport] = None


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
    # AI-generated plain-English summary of what changed between the two scans.
    # None when the AI key is not configured.
    narrative: str | None = None


class ScheduledScanCreate(BaseModel):
    url: str = Field(..., description="The URL to scan on a schedule")
    schedule: str = Field(
        "daily",
        description="How often to run the scan. Options: 'daily', 'weekly'",
    )


class ScheduledScanResponse(BaseModel):
    id: str
    url: str
    schedule: str
    is_active: bool
    last_run_at: datetime | None = None
    last_score: int | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
