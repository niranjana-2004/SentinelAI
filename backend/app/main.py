from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.v1 import api_router
from backend.app.core.config import get_settings
from backend.app.core.errors import register_error_handlers
from backend.app.schemas.health import HealthResponse, RootResponse

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description=settings.app_description,
    version=settings.app_version,
    debug=settings.debug,
)

# Configure CORS with explicit origins and disabled credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register centralized error handlers
register_error_handlers(app)

# Include modular API v1 router
app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get(
    "/",
    response_model=RootResponse,
    summary="Root Status",
    tags=["General"],
)
async def root() -> RootResponse:
    """Root endpoint returning basic platform information."""
    return RootResponse(
        project=settings.app_name,
        message="SentinelAI backend is running!",
        version=settings.app_version,
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Root Health Check",
    tags=["Health"],
)
async def health_check() -> HealthResponse:
    """Service health check returning operational status."""
    return HealthResponse(
        status="healthy",
        service="sentinelai-backend",
    )