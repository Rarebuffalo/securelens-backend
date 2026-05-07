"""
Webhook Dispatcher
==================

Shared utility for firing HMAC-signed webhook POST requests.

Previously the dispatch logic lived inline inside scan.py. Moving it here
means both the scan router and the background scheduler can call the same
function without creating a circular import.
"""

import hashlib
import hmac
import json
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.webhook import Webhook

logger = logging.getLogger(__name__)


async def dispatch_webhooks(user_id: str, scan_data: dict, db: AsyncSession) -> None:
    """
    Fetch all active webhooks for a user and POST the scan_data payload to each.

    The payload is JSON-encoded and signed with HMAC-SHA256 if the webhook has
    a secret key set. The signature is sent in the X-SecureLens-Signature header
    so the receiving server can verify the request is genuine.

    Failures are logged but never re-raised — a broken webhook should never
    crash or block the scan response.
    """
    result = await db.execute(
        select(Webhook).where(
            Webhook.user_id == user_id,
            Webhook.is_active == True,  # noqa: E712
        )
    )
    hooks = result.scalars().all()
    if not hooks:
        return

    payload = json.dumps(scan_data).encode("utf-8")

    async with httpx.AsyncClient() as client:
        for hook in hooks:
            headers = {"Content-Type": "application/json"}
            if hook.secret_key:
                sig = hmac.new(
                    hook.secret_key.encode(), payload, hashlib.sha256
                ).hexdigest()
                headers["X-SecureLens-Signature"] = sig

            try:
                await client.post(
                    hook.target_url, content=payload, headers=headers, timeout=5.0
                )
                logger.debug(f"Webhook fired: {hook.target_url}")
            except Exception as e:
                logger.warning(f"Webhook {hook.target_url} failed: {e}")
