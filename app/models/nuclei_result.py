import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class NucleiScanResult(Base):
    """
    Stores the results of a Nuclei active scan for a given website scan.

    This is a separate table from scan_results because Nuclei runs as a
    background task after the main scan response is sent — so the two rows
    are written at different times and shouldn't be coupled in a single
    transaction.

    status values:
      "pending"   - task queued but not yet started (not currently used)
      "completed" - Nuclei ran successfully (findings may be empty)
      "skipped"   - Nuclei binary not found; active scanning not configured
      "timeout"   - Nuclei exceeded the configured timeout
      "error"     - Nuclei process failed unexpectedly
    """

    __tablename__ = "nuclei_scan_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_result_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_results.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str] = mapped_column(String(2048))
    findings: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    scan_result = relationship("ScanResult", back_populates="nuclei_result")
