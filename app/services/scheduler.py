"""
Scheduler Service
=================

Manages recurring automated scans using APScheduler with the AsyncIOScheduler
backend so it runs natively inside the same event loop as FastAPI.

How it works
------------
On startup, a single "master" job is registered that runs every hour. When
it fires, it queries the database for all active ScheduledScan rows whose
next run is due, executes the full scan pipeline (the same one the /scan
endpoint uses), saves the result, and — if the score dropped compared to
the previous run — fires the user's webhooks.

We use a one-hour polling interval rather than creating a separate APScheduler
job per URL. This avoids the complexity of dynamically adding/removing jobs
when users create or delete scheduled scans, and keeps the scheduler state
in the database (the source of truth) rather than in APScheduler's job store.

Why AsyncIOScheduler
---------------------
FastAPI is an async framework running on uvicorn. APScheduler's AsyncIOScheduler
attaches to the running event loop rather than spawning a separate thread,
so async functions like database queries and httpx calls work naturally inside
scheduler jobs without any sync/async bridging hacks.

Database sessions
-----------------
Scheduler jobs cannot use FastAPI's Depends(get_db) — that only works inside
request handlers. Instead we create sessions directly via AsyncSessionLocal,
the same session factory used by the dependency injection system.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.scheduled_scan import ScheduledScan
from app.models.scan import ScanResult
from app.models.webhook import Webhook
from app.services.scoring import calculate_layer_statuses, calculate_score
from app.services.ai import enhance_security_issues
from app.services.webhook_dispatcher import dispatch_webhooks
from app.config import settings

logger = logging.getLogger(__name__)

# Module-level scheduler instance — started in main.py lifespan.
scheduler = AsyncIOScheduler(timezone="UTC")


async def _run_single_scan(scheduled: ScheduledScan) -> None:
    """
    Executes the full scan pipeline for one ScheduledScan row and saves the
    result. If the score dropped since the last run, fires the user's webhooks.

    This mirrors the logic in scan.py/scan_website but runs outside a request
    context, so it manages its own DB session.
    """
    from app.services.scanner.transport import TransportScanner
    from app.services.scanner.ssl_checker import SSLScanner
    from app.services.scanner.headers import HeaderScanner
    from app.services.scanner.cookies import CookieScanner
    from app.services.scanner.exposure import ExposureScanner
    from app.services.scanner.dns import DNSScanner
    from app.services.scanner.ports import PortScanner
    from app.utils.validators import validate_url

    url = scheduled.url
    user_id = scheduled.user_id

    logger.info(f"Scheduled scan starting: {url} (user={user_id})")

    try:
        validated_url = validate_url(url)
    except Exception as e:
        logger.error(f"Scheduled scan skipped — invalid URL '{url}': {e}")
        return

    try:
        transport_scanner = TransportScanner()
        ssl_scanner = SSLScanner()
        header_scanner = HeaderScanner()
        cookie_scanner = CookieScanner()
        exposure_scanner = ExposureScanner()
        dns_scanner = DNSScanner()
        port_scanner = PortScanner()

        dns_task = asyncio.create_task(dns_scanner.scan(validated_url))
        port_task = asyncio.create_task(port_scanner.scan(validated_url))

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.scan_timeout),
            follow_redirects=True,
        ) as client:
            response = await client.get(validated_url)

        all_issues = []
        all_issues.extend(await transport_scanner.scan(validated_url, response))
        all_issues.extend(await ssl_scanner.scan(validated_url, response))
        all_issues.extend(await header_scanner.scan(validated_url, response))
        all_issues.extend(await cookie_scanner.scan(validated_url, response))
        all_issues.extend(await exposure_scanner.scan(validated_url, response))
        all_issues.extend(await dns_task)
        all_issues.extend(await port_task)

        score = calculate_score(all_issues)
        layers = calculate_layer_statuses(all_issues)

        if settings.effective_ai_key and all_issues:
            issues_dict_list = [i.model_dump() for i in all_issues]
            ai_data = await enhance_security_issues(issues_dict_list)
            enhanced_list = ai_data.get("enhanced_issues", [])
            enhancement_map = {e.get("issue"): e for e in enhanced_list}
            for original in all_issues:
                enh = enhancement_map.get(original.issue)
                if enh:
                    original.contextual_severity = enh.get("contextual_severity")
                    original.explanation = enh.get("explanation")
                    original.remediation_snippet = enh.get("remediation_snippet")

        layers_dict = {k: v.model_dump() for k, v in layers.items()}
        issues_list = [i.model_dump() for i in all_issues]

        previous_score = scheduled.last_score

        async with AsyncSessionLocal() as db:
            # Save the new scan result
            scan_record = ScanResult(
                user_id=user_id,
                url=validated_url,
                security_score=score,
                layers=layers_dict,
                issues=issues_list,
            )
            db.add(scan_record)
            await db.flush()

            # Update the scheduled scan metadata
            scheduled_row = await db.get(ScheduledScan, scheduled.id)
            if scheduled_row:
                scheduled_row.last_run_at = datetime.now(timezone.utc)
                scheduled_row.last_score = score

            await db.commit()

            # Fire webhooks if the score dropped
            score_dropped = previous_score is not None and score < previous_score
            if score_dropped:
                delta = previous_score - score
                logger.warning(
                    f"Score dropped {delta} pts for {url} "
                    f"({previous_score} → {score}). Firing webhooks."
                )
                webhook_payload = {
                    "event": "scheduled_scan_regression",
                    "scan_id": scan_record.id,
                    "url": validated_url,
                    "score": score,
                    "previous_score": previous_score,
                    "score_delta": -delta,
                }
                await dispatch_webhooks(user_id, webhook_payload, db)

        logger.info(f"Scheduled scan complete: {url} → score={score}")

    except httpx.HTTPError as e:
        logger.error(f"Scheduled scan HTTP error for {url}: {e}")
    except Exception as e:
        logger.error(f"Scheduled scan failed for {url}: {e}", exc_info=True)


async def _run_due_scans() -> None:
    """
    Master job — runs every hour. Finds all active ScheduledScan rows that
    are due for a re-run and executes them concurrently.

    Due means:
    - daily  : last_run_at is None OR more than 24 hours ago
    - weekly : last_run_at is None OR more than 7 days ago
    """
    now = datetime.now(timezone.utc)
    thresholds = {
        "daily": now - timedelta(hours=24),
        "weekly": now - timedelta(days=7),
    }

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScheduledScan).where(ScheduledScan.is_active == True)  # noqa: E712
        )
        all_active = result.scalars().all()

    due = []
    for s in all_active:
        threshold = thresholds.get(s.schedule)
        if threshold is None:
            continue  # unknown schedule type — skip
        if s.last_run_at is None or s.last_run_at < threshold:
            due.append(s)

    if not due:
        logger.debug("Scheduled scan check: nothing due.")
        return

    logger.info(f"Running {len(due)} scheduled scan(s).")
    await asyncio.gather(*(_run_single_scan(s) for s in due))


def start_scheduler() -> None:
    """Start the APScheduler background scheduler. Called from main.py lifespan."""
    scheduler.add_job(
        _run_due_scans,
        trigger="interval",
        hours=1,
        id="scheduled_scan_master",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Scheduler started — checking for due scans every hour.")


def stop_scheduler() -> None:
    """Gracefully shut down the scheduler. Called from main.py lifespan."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped.")
