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


async def dispatch_webhooks(user_id: str, scan_data: dict, db_session):
    import hmac, hashlib, json
    from sqlalchemy import select
    
    result = await db_session.execute(
        select(Webhook).where(Webhook.user_id == user_id, Webhook.is_active == True)
    )
    hooks = result.scalars().all()
    if not hooks:
        return

    async with httpx.AsyncClient() as client:
        payload = json.dumps(scan_data).encode("utf-8")
        for hook in hooks:
            headers = {"Content-Type": "application/json"}
            if hook.secret_key:
                sig = hmac.new(hook.secret_key.encode(), payload, hashlib.sha256).hexdigest()
                headers["X-SecureLens-Signature"] = sig
            
            try:
                await client.post(hook.target_url, content=payload, headers=headers, timeout=5.0)
            except Exception as e:
                logger.warning(f"Webhook {hook.target_url} failed: {e}")


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
        import asyncio
        
        dns_task = asyncio.create_task(dns_scanner.scan(url))
        port_task = asyncio.create_task(port_scanner.scan(url))

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
        
        # Await infrastructure scans
        all_issues.extend(await dns_task)
        all_issues.extend(await port_task)

        score = calculate_score(all_issues)
        layers = calculate_layer_statuses(all_issues)

        if settings.openai_api_key and all_issues:
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

            scan_summary = {
                "scan_id": scan_id,
                "url": url,
                "score": score
            }
            background_tasks.add_task(dispatch_webhooks, current_user.id, scan_summary, db)

        return ScanResponse(
            id=scan_id,
            url=url,
            security_score=score,
            layers=layers,
            issues=all_issues,
            created_at=created_at,
        )

    except httpx.HTTPError as e:
        logger.error(f"Scan failed for {url}: {e}")
        return JSONResponse(
            status_code=502,
            content={"error": f"Could not reach {url}: {str(e)}"},
        )
