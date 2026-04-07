from fastapi import APIRouter

from app.config import settings

router = APIRouter(tags=["health"])


@router.get("/")
async def root():
    return {"message": f"{settings.app_name} backend running 🚀"}


@router.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
    }
