"""
Scheduled Scans Router
======================

CRUD endpoints for managing recurring URL scans.

POST   /scheduled-scans              — create a new scheduled scan
GET    /scheduled-scans              — list all your scheduled scans
PATCH  /scheduled-scans/{id}/toggle  — pause or resume a scheduled scan
DELETE /scheduled-scans/{id}         — delete a scheduled scan

All endpoints require authentication (JWT).
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.scheduled_scan import ScheduledScan
from app.models.user import User
from app.schemas.scan import ScheduledScanCreate, ScheduledScanResponse
from app.utils.validators import validate_url

router = APIRouter(prefix="/scheduled-scans", tags=["scheduled-scans"])


@router.post("", response_model=ScheduledScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan(
    data: ScheduledScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Register a URL for recurring automated scanning.

    The scheduler checks every hour for scans that are due (past their
    daily/weekly window) and runs them automatically. Results are saved
    to the scan history and webhooks fire if the score drops.
    """
    if data.schedule not in ("daily", "weekly"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="schedule must be 'daily' or 'weekly'",
        )

    # Validate and normalise the URL before storing
    try:
        validated_url = validate_url(data.url)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid URL: {e}",
        )

    # Prevent duplicate schedules for the same URL per user
    existing = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.user_id == current_user.id,
            ScheduledScan.url == validated_url,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A scheduled scan for this URL already exists. "
                   "Delete the existing one or use the toggle endpoint to resume it.",
        )

    scan = ScheduledScan(
        user_id=current_user.id,
        url=validated_url,
        schedule=data.schedule,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    return scan


@router.get("", response_model=list[ScheduledScanResponse])
async def list_scheduled_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return all scheduled scans belonging to the authenticated user."""
    result = await db.execute(
        select(ScheduledScan)
        .where(ScheduledScan.user_id == current_user.id)
        .order_by(ScheduledScan.created_at.desc())
    )
    return result.scalars().all()


@router.patch("/{scan_id}/toggle", response_model=ScheduledScanResponse)
async def toggle_scheduled_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Flip the is_active flag on a scheduled scan.

    Active → paused: the scan is skipped by the scheduler until resumed.
    Paused → active: the scan is eligible for the next scheduler run.
    When re-activating, last_run_at is cleared so the scan runs immediately
    on the next scheduler tick rather than waiting for the full window.
    """
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.id == scan_id,
            ScheduledScan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled scan not found")

    scan.is_active = not scan.is_active

    # Clear last_run_at when re-activating so the next scheduler tick picks it up immediately
    if scan.is_active:
        scan.last_run_at = None

    await db.flush()
    await db.refresh(scan)
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete a scheduled scan."""
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.id == scan_id,
            ScheduledScan.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled scan not found")

    await db.delete(scan)
