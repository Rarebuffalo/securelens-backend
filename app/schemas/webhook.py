from datetime import datetime
from pydantic import BaseModel, ConfigDict, HttpUrl


class WebhookCreate(BaseModel):
    target_url: HttpUrl
    secret_key: str | None = None


class WebhookResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_url: str
    is_active: bool
    created_at: datetime
