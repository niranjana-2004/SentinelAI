import logging
from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.core.config import Settings, get_settings
from backend.app.schemas.scans import (
    ApprovedTargetsResponse,
    ScanImageRequest,
    ScanResultResponse,
)
from backend.app.services.scan_repository import ScanRepository, get_scan_repository
from backend.app.services.trivy_scanner import (
    ScannerExecutionError,
    ScannerNotInstalledError,
    ScannerTimeoutError,
    TrivyScannerService,
    UnapprovedTargetError,
    get_trivy_scanner_service,
)

logger = logging.getLogger("sentinelai.api.scans")

router = APIRouter()


@router.post(
    "/image",
    response_model=ScanResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger Container Image Vulnerability Scan",
    description="Scan a pre-approved container image for known security vulnerabilities using Trivy.",
)
async def scan_image(
    request: ScanImageRequest,
    scanner: TrivyScannerService = Depends(get_trivy_scanner_service),
) -> ScanResultResponse:
    """Execute a vulnerability scan on a permitted target image."""
    try:
        return scanner.scan_image(request.image_name)
    except UnapprovedTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except ScannerNotInstalledError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vulnerability scanner service is currently unavailable on host.",
        ) from exc
    except ScannerTimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Vulnerability scan operation timed out.",
        ) from exc
    except ScannerExecutionError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Vulnerability scanner process execution failed.",
        ) from exc


@router.get(
    "/targets",
    response_model=ApprovedTargetsResponse,
    status_code=status.HTTP_200_OK,
    summary="List Approved Scan Targets",
    description="Retrieve the strict allowlist of container images authorized for vulnerability scanning.",
)
async def list_approved_targets(
    settings: Settings = Depends(get_settings),
) -> ApprovedTargetsResponse:
    """Return list of authorized container images."""
    return ApprovedTargetsResponse(
        allowed_targets=settings.approved_scan_images,
        total=len(settings.approved_scan_images),
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Scan Result by ID",
    description="Fetch a stored scan result from the in-memory repository using its scan UUID.",
)
async def get_scan_result(
    scan_id: str,
    repository: ScanRepository = Depends(get_scan_repository),
) -> ScanResultResponse:
    """Retrieve scan result by ID from the transient in-memory repository."""
    scan = repository.get(scan_id)
    if not scan:
        logger.debug("Scan ID '%s' not found in repository", scan_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' was not found.",
        )
    return scan
