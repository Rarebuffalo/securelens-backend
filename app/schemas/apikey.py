from datetime import datetime
from pydantic import BaseModel


class ApiKeyCreate(BaseModel):
    name: str


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    created_at: datetime


class ApiKeyCreateResponse(ApiKeyResponse):
    key: str  # The raw API key returned only once upon creation
