from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

class SeverityLevel(str, Enum):
    """Normalized vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ScanStatus(str, Enum):
    """Vulnerability scan execution status."""

    COMPLETED = "completed"
    FAILED = "failed"


class VulnerabilityItem(BaseModel):
    """Normalized representation of a single detected vulnerability finding."""

    vulnerability_id: str = Field(..., description="CVE or vulnerability identifier (e.g. CVE-2023-45853)")
    package_name: str = Field(..., description="Vulnerable package or library name")
    installed_version: str = Field(..., description="Installed package version detected in the image")
    fixed_version: Optional[str] = Field(None, description="Patched version resolving the vulnerability, if available")
    severity: SeverityLevel = Field(default=SeverityLevel.UNKNOWN, description="Normalized severity level")
    risk_score: Optional[float] = Field(
        None,
        description="Calculated risk score for the vulnerability",
    )
    remediation_guidance: Optional[str] = Field(
    None,
    description="Recommended remediation action based on severity",
)
    title: Optional[str] = Field(None, description="Short summary of the vulnerability")
    description: Optional[str] = Field(None, description="Detailed explanation of the security finding")
    primary_url: Optional[str] = Field(None, description="Reference link to official advisory or CVE entry")
    target: str = Field(..., description="Target file, component, or OS layer (e.g. debian 12.5, python)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "vulnerability_id": "CVE-2023-45853",
                "package_name": "zlib1g",
                "installed_version": "1:1.2.13.dfsg-1",
                "fixed_version": "1:1.2.13.dfsg-1+deb12u1",
                "severity": "CRITICAL",
                "risk_score": 9.8,
                "remediation_guidance": "Upgrade to version 1:1.2.13.dfsg-1+deb12u1",
                "title": "zlib MiniZip buffer overflow",
                "description": "MiniZip in zlib allows integer overflow and resultant buffer overflow.",
                "primary_url": "https://avd.aquasec.com/nvd/cve-2023-45853",
                "target": "python:3.12-slim (debian 12.5)"
            }
        }
    )


class VulnerabilitySummary(BaseModel):
    """Aggregated count of vulnerabilities by severity level."""

    total: int = Field(default=0, description="Total number of detected vulnerabilities")
    critical: int = Field(default=0, description="Count of critical severity findings")
    high: int = Field(default=0, description="Count of high severity findings")
    medium: int = Field(default=0, description="Count of medium severity findings")
    low: int = Field(default=0, description="Count of low severity findings")
    unknown: int = Field(default=0, description="Count of unclassified severity findings")


class ScanResultResponse(BaseModel):
    """Complete result model for a completed or failed vulnerability scan."""

    scan_id: str = Field(..., description="Unique UUID identifying the scan execution")
    target_image: str = Field(..., description="Container image that was scanned")
    scanner: str = Field(default="Trivy", description="Security scanner tool identifier")
    status: ScanStatus = Field(..., description="Status of the scan execution")
    scanned_at: datetime = Field(..., description="Timestamp when the scan finished")
    duration_seconds: float = Field(..., description="Subprocess execution duration in seconds")
    summary: VulnerabilitySummary = Field(
        default_factory=VulnerabilitySummary,
        description="Aggregated vulnerability severity counts",
    )
    vulnerabilities: list[VulnerabilityItem] = Field(
        default_factory=list,
        description="List of normalized vulnerability findings",
    )
    error_message: Optional[str] = Field(
        None,
        description="Error details if the scan failed",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "scan_id": "8b52cf66-fbf3-4eb8-b986-e8d98d248b11",
                "target_image": "python:3.12-slim",
                "scanner": "Trivy",
                "status": "completed",
                "scanned_at": "2026-10-13T21:50:00Z",
                "duration_seconds": 1.42,
                "summary": {
                    "total": 1,
                    "critical": 1,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                },
                "vulnerabilities": [],
                "error_message": None,
            }
        }
    )


class ScanImageRequest(BaseModel):
    """Request payload to trigger a container image vulnerability scan."""

    image_name: str = Field(
        ...,
        description="Exact container image tag from the approved allowlist (e.g. python:3.12-slim)",
        examples=["python:3.12-slim"],
    )


class ApprovedTargetsResponse(BaseModel):
    """Response payload listing pre-approved container images."""

    allowed_targets: list[str] = Field(..., description="List of container images permitted for scanning")
    total: int = Field(..., description="Total count of allowed images")
