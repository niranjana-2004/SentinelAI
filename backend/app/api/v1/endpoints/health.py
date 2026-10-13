from fastapi import APIRouter

from backend.app.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="API v1 Health Check")
async def health_check() -> HealthResponse:
    """Return operational health status for API v1."""
    return HealthResponse(
        status="healthy",
        service="sentinelai-backend",
    )
