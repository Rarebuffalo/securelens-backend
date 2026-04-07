from datetime import datetime
from pydantic import BaseModel, HttpUrl


class WebhookCreate(BaseModel):
    target_url: HttpUrl
    secret_key: str | None = None


class WebhookResponse(BaseModel):
    id: str
    target_url: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True
