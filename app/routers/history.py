from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.scan import ScanResult
from app.models.user import User
from app.schemas.scan import (
    Issue,
    LayerStatus,
    ScanHistoryItem,
    ScanHistoryResponse,
    ScanResponse,
    DashboardTrendsResponse,
    ChatRequest,
    ChatResponse,
    ThreatNarrativeResponse,
    ScanDiffResponse,
    ScheduledScanResponse,
)

from app.services.ai import chat_with_scan_context, generate_threat_narrative, generate_diff_narrative

router = APIRouter(prefix="/scans", tags=["history"])


@router.get("", response_model=ScanHistoryResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * per_page

    count_result = await db.execute(
        select(func.count()).select_from(ScanResult).where(ScanResult.user_id == current_user.id)
    )
    total = count_result.scalar_one()

    result = await db.execute(
        select(ScanResult)
        .where(ScanResult.user_id == current_user.id)
        .order_by(ScanResult.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    scans = result.scalars().all()

    return ScanHistoryResponse(
        scans=[ScanHistoryItem.model_validate(s) for s in scans],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/trends", response_model=DashboardTrendsResponse)
async def get_trends(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    count_result = await db.execute(
        select(func.count()).select_from(ScanResult).where(ScanResult.user_id == current_user.id)
    )
    total_scans = count_result.scalar_one()

    avg_result = await db.execute(
        select(func.avg(ScanResult.security_score)).where(ScanResult.user_id == current_user.id)
    )
    avg_score = avg_result.scalar_one() or 0.0

    recent_result = await db.execute(
        select(ScanResult)
        .where(ScanResult.user_id == current_user.id)
        .order_by(ScanResult.created_at.desc())
        .limit(5)
    )
    recent_scans = recent_result.scalars().all()

    return DashboardTrendsResponse(
        total_scans=total_scans,
        average_score=float(avg_score),
        recent_scans=[ScanHistoryItem.model_validate(s) for s in recent_scans]
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    return ScanResponse(
        id=scan.id,
        url=scan.url,
        security_score=scan.security_score,
        layers={k: LayerStatus(**v) for k, v in scan.layers.items()},
        issues=[Issue(**i) for i in scan.issues],
        created_at=scan.created_at,
    )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    await db.delete(scan)


@router.post("/{scan_id}/chat", response_model=ChatResponse)
async def chat_about_scan(
    scan_id: str,
    data: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    context_data = {
        "url": scan.url,
        "score": scan.security_score,
        "layers": scan.layers,
        "issues": scan.issues,
    }

    reply = await chat_with_scan_context(scan_id, context_data, data.message)
    return ChatResponse(reply=reply)


@router.get("/{scan_id}/threat-narrative", response_model=ThreatNarrativeResponse)
async def get_threat_narrative(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id == scan_id,
            ScanResult.user_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    context_data = {
        "url": scan.url,
        "score": scan.security_score,
        "layers": scan.layers,
        "issues": scan.issues,
    }

    narrative = await generate_threat_narrative(context_data)
    return ThreatNarrativeResponse(narrative=narrative)


@router.get("/{old_id}/diff/{new_id}", response_model=ScanDiffResponse)
async def diff_scans(
    old_id: str,
    new_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanResult).where(
            ScanResult.id.in_([old_id, new_id]),
            ScanResult.user_id == current_user.id
        )
    )
    scans = result.scalars().all()

    if len(scans) != 2:
        raise HTTPException(status_code=404, detail="One or both scans not found, or access denied.")

    s_old = scans[0] if scans[0].id == old_id else scans[1]
    s_new = scans[1] if scans[1].id == new_id else scans[0]

    # Map issues by name for set-like comparison
    old_map = {i.get("issue"): i for i in s_old.issues}
    new_map = {i.get("issue"): i for i in s_new.issues}

    resolved = [v for k, v in old_map.items() if k not in new_map]
    new_issues = [v for k, v in new_map.items() if k not in old_map]
    persisting = [v for k, v in new_map.items() if k in old_map]
    score_change = s_new.security_score - s_old.security_score

    # Ask the AI to narrate the changes in plain English
    diff_context = {
        "score_change": score_change,
        "resolved_issues": resolved,
        "new_issues": new_issues,
        "persisting_issues": persisting,
    }
    narrative = await generate_diff_narrative(diff_context)

    return ScanDiffResponse(
        resolved_issues=resolved,
        new_issues=new_issues,
        persisting_issues=persisting,
        score_change=score_change,
        narrative=narrative,
    )
