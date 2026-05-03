import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CodeScanResult(Base):
    """
    Persists the result of an AI-powered code repository scan to the database.

    Why this exists:
    - Previously, code scan results were stored in a plain Python dict (scan_store)
      in memory. This caused data loss on every server restart and prevented the
      chat feature from working reliably. This model fixes that permanently.

    Columns:
    - id:           UUID primary key, used as the scan_id returned to the client.
    - user_id:      Optional FK to users table. NULL for unauthenticated scans.
    - repo_url:     The GitHub repository URL that was scanned.
    - summary:      The AI-generated executive summary of the scan.
    - issues:       JSON list of VulnerabilityIssue dicts.
    - created_at:   Timestamp of when the scan was performed.
    """

    __tablename__ = "code_scan_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), index=True, nullable=True
    )
    repo_url: Mapped[str] = mapped_column(String(2048))
    summary: Mapped[str] = mapped_column(Text, default="")
    issues: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user = relationship("User", back_populates="code_scans")
