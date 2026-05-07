import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ScheduledScan(Base):
    """
    Represents a user-configured recurring scan for a URL.

    schedule  : "daily" or "weekly" — controls how the APScheduler job
                triggers re-scans.
    last_run_at : timestamp of the last completed scheduled scan.
    last_score  : security score from the last run, used to detect regressions.
                  If the new score is lower, a webhook is fired.
    is_active   : soft toggle — paused scans stay in the DB but are skipped
                  by the scheduler.
    """

    __tablename__ = "scheduled_scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str] = mapped_column(String(2048))
    schedule: Mapped[str] = mapped_column(String(10), default="daily")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    last_score: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user = relationship("User", back_populates="scheduled_scans")
