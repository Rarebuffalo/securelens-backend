import asyncio
import logging

import httpx
from fastapi import APIRouter, Depends, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.middleware.auth import get_optional_user
from app.middleware.rate_limiter import limiter
from app.models.scan import ScanResult
from app.models.user import User
from app.models.webhook import Webhook
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.scanner.cookies import CookieScanner
from app.services.scanner.exposure import ExposureScanner
from app.services.scanner.headers import HeaderScanner
from app.services.scanner.ssl_checker import SSLScanner
from app.services.scanner.transport import TransportScanner
from app.services.scanner.dns import DNSScanner
from app.services.scanner.ports import PortScanner
from app.services.scoring import calculate_layer_statuses, calculate_score
from app.services.ai import enhance_security_issues
from app.services.threat_intel import get_threat_intel_summary
from app.services.webhook_dispatcher import dispatch_webhooks
from app.services.nuclei_scanner import run_nuclei_scan
from app.services.alerting import (
    send_slack_alert,
    send_email_alert,
    build_scan_email_body,
)
from app.utils.validators import validate_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scan"])

transport_scanner = TransportScanner()
ssl_scanner = SSLScanner()
header_scanner = HeaderScanner()
cookie_scanner = CookieScanner()
exposure_scanner = ExposureScanner()
dns_scanner = DNSScanner()
port_scanner = PortScanner()


async def _post_scan_tasks(
    user_id: str,
    user_email: str,
    scan_id: str,
    url: str,
    score: int,
    issue_count: int,
    db: AsyncSession,
) -> None:
    """
    Groups all post-scan side-effects that run as a background task:
      - Dispatch webhooks
      - Send Slack alert
      - Send email alert
      - Trigger Nuclei active scan

    These all run after the response has been sent to the client, so they
    never add latency to the scan endpoint.
    """
    scan_summary = {"scan_id": scan_id, "url": url, "score": score}
    await dispatch_webhooks(user_id, scan_summary, db)

    slack_msg = f"URL: {url}\nScore: {score}/100  |  Issues found: {issue_count}"
    await send_slack_alert(title="SecureLens Scan Complete", message=slack_msg)

    email_body = build_scan_email_body(url, score, issue_count)
    await send_email_alert(
        to_email=user_email,
        subject=f"SecureLens: Scan complete for {url}",
        html_body=email_body,
    )

    # Nuclei runs last — it creates its own DB session and takes the longest
    await run_nuclei_scan(scan_id, url)


@router.post("/scan", response_model=ScanResponse)
@limiter.limit(settings.rate_limit)
async def scan_website(
    data: ScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    url = validate_url(data.url)

    try:
        dns_task = asyncio.create_task(dns_scanner.scan(url))
        port_task = asyncio.create_task(port_scanner.scan(url))
        threat_intel_task = asyncio.create_task(get_threat_intel_summary(url))

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.scan_timeout),
            follow_redirects=True,
        ) as client:
            response = await client.get(url)

        all_issues = []
        all_issues.extend(await transport_scanner.scan(url, response))
        all_issues.extend(await ssl_scanner.scan(url, response))
        all_issues.extend(await header_scanner.scan(url, response))
        all_issues.extend(await cookie_scanner.scan(url, response))
        all_issues.extend(await exposure_scanner.scan(url, response))
        all_issues.extend(await dns_task)
        all_issues.extend(await port_task)
        threat_intel = await threat_intel_task

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

        scan_id = None
        created_at = None

        if current_user is not None:
            layers_dict = {k: v.model_dump() for k, v in layers.items()}
            issues_list = [i.model_dump() for i in all_issues]

            scan_record = ScanResult(
                user_id=current_user.id,
                url=url,
                security_score=score,
                layers=layers_dict,
                issues=issues_list,
            )
            db.add(scan_record)
            await db.flush()
            scan_id = scan_record.id
            created_at = scan_record.created_at

            background_tasks.add_task(
                _post_scan_tasks,
                current_user.id,
                current_user.email,
                scan_id,
                url,
                score,
                len(all_issues),
                db,
            )

        return ScanResponse(
            id=scan_id,
            url=url,
            security_score=score,
            layers=layers,
            issues=all_issues,
            created_at=created_at,
            threat_intel=threat_intel,
        )

    except httpx.HTTPError as e:
        logger.error(f"Scan failed for {url}: {e}")
        return JSONResponse(
            status_code=502,
            content={"error": f"Could not reach {url}: {str(e)}"},
        )

