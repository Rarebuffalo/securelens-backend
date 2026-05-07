import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), index=True
    )
    url: Mapped[str] = mapped_column(String(2048))
    security_score: Mapped[int] = mapped_column(Integer)
    layers: Mapped[dict] = mapped_column(JSON)
    issues: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user = relationship("User", back_populates="scans")
    nuclei_result = relationship("NucleiScanResult", back_populates="scan_result", uselist=False, cascade="all, delete")
