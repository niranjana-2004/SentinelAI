from datetime import datetime, timezone
import logging
import os
import subprocess
import time
import uuid

from backend.app.core.config import Settings, get_settings
from backend.app.schemas.scans import (
    ScanResultResponse,
    ScanStatus,
    VulnerabilitySummary,
)
from backend.app.services.scan_repository import ScanRepository, get_scan_repository
from backend.app.services.trivy_parser import TrivyParseError, parse_trivy_json

logger = logging.getLogger("sentinelai.trivy_scanner")


class ScannerException(Exception):
    """Base exception for vulnerability scanner failures."""
    pass


ScannerError = ScannerException


class UnapprovedTargetError(ScannerException):
    """Raised when an unapproved container image is submitted."""
    pass


class ScannerNotInstalledError(ScannerException):
    """Raised when the Trivy binary is not found on host."""
    pass


class ScannerTimeoutError(ScannerException):
    """Raised when scan execution exceeds configured timeout."""
    pass


class ScannerExecutionError(ScannerException):
    """Raised when scanner fails with non-zero exit code or produces corrupt output."""
    pass


class TrivyScannerService:
    """Service executing Trivy CLI scans safely via subprocess with timeouts and target allowlist."""

    def __init__(
        self,
        settings: Settings | None = None,
        repository: ScanRepository | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.repository = repository or get_scan_repository()

    def validate_target(self, image_name: str) -> str:
        """Validate that the image is an exact match in the approved target allowlist.

        Returns cleaned image name if approved.
        Raises UnapprovedTargetError if not approved.
        """
        cleaned = (image_name or "").strip()
        if not cleaned or cleaned not in self.settings.approved_scan_images:
            logger.warning("Rejected unapproved scan target request: '%s'", cleaned)
            raise UnapprovedTargetError(
                f"Image target '{cleaned}' is not authorized. Allowed targets: {self.settings.approved_scan_images}"
            )
        return cleaned

    def scan_image(self, image_name: str) -> ScanResultResponse:
        """Execute a controlled vulnerability scan against an approved container image.

        Args:
            image_name: Exact tag of the container image to scan.

        Returns:
            A completed ScanResultResponse with parsed vulnerability items.

        Raises:
            UnapprovedTargetError: If target image is not in the allowlist.
            ScannerNotInstalledError: If Trivy binary is missing.
            ScannerTimeoutError: If subprocess runs longer than scan_timeout_seconds.
            ScannerExecutionError: If Trivy process fails with non-zero exit code.
        """
        valid_target = self.validate_target(image_name)
        scan_id = str(uuid.uuid4())

        # Ensure cache directory exists on designated volume
        try:
            os.makedirs(self.settings.trivy_cache_dir, exist_ok=True)
        except OSError as exc:
            logger.warning("Could not pre-create Trivy cache directory: %s", exc)

        args = [
            self.settings.trivy_binary_path,
            "image",
            "--format",
            "json",
            "--quiet",
            "--no-progress",
            "--cache-dir",
            self.settings.trivy_cache_dir,
            valid_target,
        ]

        logger.info("Starting Trivy scan %s for image '%s'", scan_id, valid_target)
        start_time = time.perf_counter()

        try:
            process = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.settings.scan_timeout_seconds,
                shell=False,
            )
        except FileNotFoundError as exc:
            logger.error("Trivy executable '%s' not found on system PATH", self.settings.trivy_binary_path)
            failed_scan = ScanResultResponse(
                scan_id=scan_id,
                target_image=valid_target,
                scanner="Trivy",
                status=ScanStatus.FAILED,
                scanned_at=datetime.now(timezone.utc),
                duration_seconds=0.0,
                summary=VulnerabilitySummary(),
                vulnerabilities=[],
                error_message="Vulnerability scanner executable is not available on host system.",
            )
            self.repository.save(failed_scan)
            raise ScannerNotInstalledError("Trivy CLI executable was not found.") from exc
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - start_time
            logger.warning(
                "Scan %s for image '%s' timed out after %ds",
                scan_id,
                valid_target,
                self.settings.scan_timeout_seconds,
            )
            failed_scan = ScanResultResponse(
                scan_id=scan_id,
                target_image=valid_target,
                scanner="Trivy",
                status=ScanStatus.FAILED,
                scanned_at=datetime.now(timezone.utc),
                duration_seconds=round(duration, 3),
                summary=VulnerabilitySummary(),
                vulnerabilities=[],
                error_message=f"Scan timed out after {self.settings.scan_timeout_seconds} seconds.",
            )
            self.repository.save(failed_scan)
            raise ScannerTimeoutError(
                f"Scan timed out after {self.settings.scan_timeout_seconds} seconds."
            ) from exc

        duration = time.perf_counter() - start_time

        if process.returncode != 0:
            stderr_sample = (process.stderr or "").strip()[:500]
            logger.error(
                "Trivy scan %s failed with exit code %d: %s",
                scan_id,
                process.returncode,
                stderr_sample,
            )
            failed_scan = ScanResultResponse(
                scan_id=scan_id,
                target_image=valid_target,
                scanner="Trivy",
                status=ScanStatus.FAILED,
                scanned_at=datetime.now(timezone.utc),
                duration_seconds=round(duration, 3),
                summary=VulnerabilitySummary(),
                vulnerabilities=[],
                error_message=f"Vulnerability scanner process failed with exit code {process.returncode}.",
            )
            self.repository.save(failed_scan)
            raise ScannerExecutionError(
                f"Vulnerability scanner failed with exit code {process.returncode}."
            )

        try:
            scan_result = parse_trivy_json(
                raw_output=process.stdout,
                scan_id=scan_id,
                target_image=valid_target,
                duration_seconds=duration,
            )
            self.repository.save(scan_result)
            logger.info(
                "Scan %s for '%s' completed successfully in %.2fs with %d findings",
                scan_id,
                valid_target,
                duration,
                scan_result.summary.total,
            )
            return scan_result
        except TrivyParseError as exc:
            logger.error("Scan %s produced unparseable JSON output: %s", scan_id, exc)
            failed_scan = ScanResultResponse(
                scan_id=scan_id,
                target_image=valid_target,
                scanner="Trivy",
                status=ScanStatus.FAILED,
                scanned_at=datetime.now(timezone.utc),
                duration_seconds=round(duration, 3),
                summary=VulnerabilitySummary(),
                vulnerabilities=[],
                error_message="Vulnerability scanner produced invalid output format.",
            )
            self.repository.save(failed_scan)
            raise ScannerExecutionError("Scanner output could not be parsed.") from exc


def get_trivy_scanner_service() -> TrivyScannerService:
    """Dependency provider for TrivyScannerService."""
    return TrivyScannerService()
