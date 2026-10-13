from fastapi import APIRouter

from backend.app.api.v1.endpoints import health, scans

api_router = APIRouter()

# Register modular sub-routers
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
