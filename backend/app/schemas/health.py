from pydantic import BaseModel, ConfigDict, Field


class RootResponse(BaseModel):
    """Schema for root endpoint response."""

    project: str = Field(..., description="Project name", examples=["SentinelAI"])
    message: str = Field(..., description="Status message", examples=["SentinelAI backend is running!"])
    version: str = Field(..., description="Current application version", examples=["0.1.0"])

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "project": "SentinelAI",
                "message": "SentinelAI backend is running!",
                "version": "0.1.0",
            }
        }
    )


class HealthResponse(BaseModel):
    """Schema for health check endpoint response."""

    status: str = Field(..., description="Service operational status", examples=["healthy"])
    service: str = Field(..., description="Service identifier", examples=["sentinelai-backend"])

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "service": "sentinelai-backend",
            }
        }
    )
