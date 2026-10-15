from datetime import datetime, timezone
import json
import logging
from typing import Any, Optional

from backend.app.schemas.scans import (
    ScanResultResponse,
    ScanStatus,
    SeverityLevel,
    VulnerabilityItem,
    VulnerabilitySummary,
)
from backend.app.services.risk_engine import RiskPrioritizationEngine

logger = logging.getLogger("sentinelai.trivy_parser")


class TrivyParseError(ValueError):
    """Raised when raw scanner output cannot be parsed as valid Trivy JSON."""
    pass


def normalize_severity(severity_raw: Optional[str]) -> SeverityLevel:
    """Safely map raw severity strings to normalized SeverityLevel enum values."""
    if not severity_raw or not isinstance(severity_raw, str):
        return SeverityLevel.UNKNOWN
    cleaned = severity_raw.strip().upper()
    try:
        return SeverityLevel(cleaned)
    except ValueError:
        logger.debug("Unrecognized vulnerability severity '%s', defaulting to UNKNOWN", severity_raw)
        return SeverityLevel.UNKNOWN


def parse_trivy_json(
    raw_output: str,
    scan_id: str,
    target_image: str,
    duration_seconds: float,
) -> ScanResultResponse:
    """Parse raw Trivy JSON output into a normalized ScanResultResponse.

    Args:
        raw_output: Raw JSON stdout string produced by Trivy CLI.
        scan_id: Unique UUID generated for this scan execution.
        target_image: Name/tag of the scanned container image.
        duration_seconds: Subprocess execution runtime in seconds.

    Returns:
        A validated ScanResultResponse containing normalized vulnerability items and summary.

    Raises:
        TrivyParseError: If raw_output is invalid JSON or has unexpected structure.
    """
    if not raw_output or not raw_output.strip():
        # An empty output from a successful command with no findings
        return ScanResultResponse(
            scan_id=scan_id,
            target_image=target_image,
            scanner="Trivy",
            status=ScanStatus.COMPLETED,
            scanned_at=datetime.now(timezone.utc),
            duration_seconds=round(duration_seconds, 3),
            summary=VulnerabilitySummary(),
            vulnerabilities=[],
            error_message=None,
        )

    try:
        data: Any = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        logger.error("Failed to decode Trivy JSON output: %s", str(exc))
        raise TrivyParseError(f"Malformed JSON output from Trivy scanner: {exc}") from exc

    if not isinstance(data, dict):
        raise TrivyParseError("Expected top-level JSON object from Trivy scanner output.")

    vulnerabilities: list[VulnerabilityItem] = []
    summary_counts = {
        SeverityLevel.CRITICAL: 0,
        SeverityLevel.HIGH: 0,
        SeverityLevel.MEDIUM: 0,
        SeverityLevel.LOW: 0,
        SeverityLevel.UNKNOWN: 0,
    }

    results = data.get("Results") or []
    if isinstance(results, list):
        for result_block in results:
            if not isinstance(result_block, dict):
                continue
            target_name = str(result_block.get("Target") or target_image).strip()
            raw_vulns = result_block.get("Vulnerabilities") or []
            if not isinstance(raw_vulns, list):
                continue

            for vuln in raw_vulns:
                if not isinstance(vuln, dict):
                    continue

                vuln_id = str(vuln.get("VulnerabilityID") or "").strip()
                pkg_name = str(vuln.get("PkgName") or "").strip()
                installed_ver = str(vuln.get("InstalledVersion") or "").strip()

                # Skip completely blank vulnerability records
                if not vuln_id and not pkg_name:
                    continue

                severity = normalize_severity(vuln.get("Severity"))
                summary_counts[severity] += 1

                fixed_version = vuln.get("FixedVersion")
                if fixed_version is not None:
                    fixed_version = str(fixed_version).strip() or None

                title = vuln.get("Title")
                if title is not None:
                    title = str(title).strip() or None

                description = vuln.get("Description")
                if description is not None:
                    description = str(description).strip() or None

                primary_url = vuln.get("PrimaryURL")
                if primary_url is not None:
                    primary_url = str(primary_url).strip() or None

                risk_score = RiskPrioritizationEngine.get_severity_score(severity)
                remediation_guidance = (
                    RiskPrioritizationEngine.get_remediation_guidance(
                        severity,
                        fixed_version=fixed_version,
                    )
                )

                vulnerabilities.append(
                    VulnerabilityItem(
                        vulnerability_id=vuln_id or "UNKNOWN-ID",
                        package_name=pkg_name or "unknown-package",
                        installed_version=installed_ver or "unknown",
                        fixed_version=fixed_version,
                        severity=severity,
                        risk_score=risk_score,
                        remediation_guidance=remediation_guidance,
                        title=title,
                        description=description,
                        primary_url=primary_url,
                        target=target_name,
                    )
                )

    summary = VulnerabilitySummary(
        total=len(vulnerabilities),
        critical=summary_counts[SeverityLevel.CRITICAL],
        high=summary_counts[SeverityLevel.HIGH],
        medium=summary_counts[SeverityLevel.MEDIUM],
        low=summary_counts[SeverityLevel.LOW],
        unknown=summary_counts[SeverityLevel.UNKNOWN],
    )

    return ScanResultResponse(
        scan_id=scan_id,
        target_image=target_image,
        scanner="Trivy",
        status=ScanStatus.COMPLETED,
        scanned_at=datetime.now(timezone.utc),
        duration_seconds=round(duration_seconds, 3),
        summary=summary,
        vulnerabilities=vulnerabilities,
        error_message=None,
    )
