import secrets
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.user import User
from app.models.webhook import Webhook
from app.schemas.webhook import WebhookCreate, WebhookResponse

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("", response_model=WebhookResponse)
async def create_webhook(
    hook_in: WebhookCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    secret = hook_in.secret_key or secrets.token_hex(16)
    db_hook = Webhook(
        user_id=current_user.id,
        target_url=str(hook_in.target_url),
        secret_key=secret
    )
    db.add(db_hook)
    await db.commit()
    await db.refresh(db_hook)
    return db_hook


@router.get("", response_model=list[WebhookResponse])
async def list_webhooks(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Webhook).where(Webhook.user_id == current_user.id))
    return result.scalars().all()


@router.delete("/{hook_id}")
async def delete_webhook(
    hook_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Webhook).where(Webhook.id == hook_id, Webhook.user_id == current_user.id))
    hook = result.scalar_one_or_none()
    
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook not found")
        
    await db.delete(hook)
    await db.commit()
    return {"status": "success", "message": "Webhook deleted"}
