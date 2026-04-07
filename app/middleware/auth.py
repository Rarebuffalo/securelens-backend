from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import hashlib

from app.database import get_db
from app.models.user import User
from app.models.apikey import ApiKey
from app.utils.auth import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    api_key: str | None = Depends(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> User:
    if token:
        user_id = decode_access_token(token)
        if user_id:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if user:
                return user

    if api_key:
        hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
        result = await db.execute(
            select(User)
            .join(ApiKey, User.id == ApiKey.user_id)
            .where(ApiKey.hashed_key == hashed_key)
        )
        user = result.scalar_one_or_none()
        if user:
            return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_optional_user(
    token: str | None = Depends(oauth2_scheme),
    api_key: str | None = Depends(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    if token:
        user_id = decode_access_token(token)
        if user_id:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if user:
                return user
                
    if api_key:
        hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
        result = await db.execute(
            select(User)
            .join(ApiKey, User.id == ApiKey.user_id)
            .where(ApiKey.hashed_key == hashed_key)
        )
        user = result.scalar_one_or_none()
        if user:
            return user

    return None
