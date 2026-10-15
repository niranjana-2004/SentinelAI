from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import pytest

from backend.app.schemas.scans import (
    ScanResultResponse,
    ScanStatus,
    SeverityLevel,
    VulnerabilitySummary,
)
from backend.app.services.scan_repository import ScanRepository
from backend.app.services.trivy_parser import (
    TrivyParseError,
    normalize_severity,
    parse_trivy_json,
)
from backend.app.services.trivy_scanner import (
    ScannerExecutionError,
    ScannerNotInstalledError,
    ScannerTimeoutError,
    TrivyScannerService,
    UnapprovedTargetError,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "trivy_sample_output.json"


@pytest.fixture
def sample_trivy_json() -> str:
    """Load sample sanitized Trivy JSON output fixture."""
    return FIXTURE_PATH.read_text(encoding="utf-8")


@pytest.fixture
def fresh_repository() -> ScanRepository:
    """Provide an isolated in-memory repository for unit testing."""
    return ScanRepository(max_items=5)


# ---------------------------------------------------------------------------
# Parser Unit Tests
# ---------------------------------------------------------------------------


def test_normalize_severity() -> None:
    """Verify severity normalizer maps strings properly and falls back to UNKNOWN."""
    assert normalize_severity("CRITICAL") == SeverityLevel.CRITICAL
    assert normalize_severity("high") == SeverityLevel.HIGH
    assert normalize_severity(" Medium ") == SeverityLevel.MEDIUM
    assert normalize_severity("low") == SeverityLevel.LOW
    assert normalize_severity("unknown") == SeverityLevel.UNKNOWN
    assert normalize_severity("INVALID_VAL") == SeverityLevel.UNKNOWN
    assert normalize_severity(None) == SeverityLevel.UNKNOWN


def test_parse_trivy_sample_fixture(sample_trivy_json: str) -> None:
    """Validate parsing of multi-target fixture with multiple severities."""
    result = parse_trivy_json(
        raw_output=sample_trivy_json,
        scan_id="test-scan-123",
        target_image="python:3.12-slim",
        duration_seconds=1.234,
    )
    assert result.scan_id == "test-scan-123"
    assert result.target_image == "python:3.12-slim"
    assert result.status == ScanStatus.COMPLETED
    assert result.duration_seconds == 1.234
    assert result.summary.total == 5
    assert result.summary.critical == 2
    assert result.summary.high == 1
    assert result.summary.medium == 1
    assert result.summary.low == 1
    assert result.summary.unknown == 0

    # Verify optional fields handled properly
    finding_coreutils = next(v for v in result.vulnerabilities if v.package_name == "coreutils")
    assert finding_coreutils.fixed_version is None
    assert finding_coreutils.severity == SeverityLevel.MEDIUM

    finding_tar = next(v for v in result.vulnerabilities if v.package_name == "tar")
    assert finding_tar.title is None
    assert finding_tar.description is None
    assert finding_tar.primary_url is None
    assert finding_tar.fixed_version == "1.34+dfsg-1.2+deb12u1"


def test_parse_empty_findings() -> None:
    """Validate parsing JSON from a clean image with zero findings."""
    empty_json = '{"SchemaVersion": 2, "ArtifactName": "alpine:3.19", "Results": [{"Target": "alpine", "Vulnerabilities": []}]}'
    result = parse_trivy_json(
        raw_output=empty_json,
        scan_id="test-clean",
        target_image="alpine:3.19",
        duration_seconds=0.5,
    )
    assert result.status == ScanStatus.COMPLETED
    assert result.summary.total == 0
    assert len(result.vulnerabilities) == 0


def test_parse_empty_string_output() -> None:
    """Validate empty stdout produces valid completed scan with zero findings."""
    result = parse_trivy_json(
        raw_output="   ",
        scan_id="test-empty",
        target_image="alpine:3.19",
        duration_seconds=0.1,
    )
    assert result.status == ScanStatus.COMPLETED
    assert result.summary.total == 0


def test_parse_malformed_json_raises_error() -> None:
    """Validate corrupt or non-JSON output raises TrivyParseError."""
    with pytest.raises(TrivyParseError):
        parse_trivy_json(
            raw_output="{ corrupt json content",
            scan_id="test-err",
            target_image="alpine:3.19",
            duration_seconds=0.1,
        )


# ---------------------------------------------------------------------------
# In-Memory Repository Unit Tests
# ---------------------------------------------------------------------------


def test_repository_save_and_retrieve(fresh_repository: ScanRepository) -> None:
    """Verify scan storage and lookup by ID."""
    from datetime import datetime, timezone

    scan = ScanResultResponse(
        scan_id="uuid-1",
        target_image="python:3.12-slim",
        status=ScanStatus.COMPLETED,
        scanned_at=datetime.now(timezone.utc),
        duration_seconds=1.0,
        summary=VulnerabilitySummary(),
        vulnerabilities=[],
    )
    fresh_repository.save(scan)
    retrieved = fresh_repository.get("uuid-1")
    assert retrieved is not None
    assert retrieved.scan_id == "uuid-1"
    assert fresh_repository.get("non-existent") is None


def test_repository_bounded_capacity(fresh_repository: ScanRepository) -> None:
    """Verify FIFO eviction when repository capacity (max_items=5) is exceeded."""
    from datetime import datetime, timezone

    for i in range(7):
        scan = ScanResultResponse(
            scan_id=f"uuid-{i}",
            target_image="alpine:3.19",
            status=ScanStatus.COMPLETED,
            scanned_at=datetime.now(timezone.utc),
            duration_seconds=1.0,
            summary=VulnerabilitySummary(),
            vulnerabilities=[],
        )
        fresh_repository.save(scan)

    assert fresh_repository.count() == 5
    # Earliest two records should have been evicted
    assert fresh_repository.get("uuid-0") is None
    assert fresh_repository.get("uuid-1") is None
    # Most recent records should still exist
    assert fresh_repository.get("uuid-5") is not None
    assert fresh_repository.get("uuid-6") is not None


# ---------------------------------------------------------------------------
# Scanner Service Subprocess Unit Tests (Mocked)
# ---------------------------------------------------------------------------


def test_scanner_service_unapproved_target_rejected() -> None:
    """Verify target validation rejects unauthorized images without invoking subprocess."""
    service = TrivyScannerService()
    with pytest.raises(UnapprovedTargetError):
        service.scan_image("unauthorized/malicious-image:latest")


@patch("subprocess.run")
def test_scanner_service_success_mocked(
    mock_subproc: MagicMock,
    sample_trivy_json: str,
) -> None:
    """Verify successful scanner execution parses and stores results."""
    mock_subproc.return_value = subprocess.CompletedProcess(
        args=["trivy", "image"],
        returncode=0,
        stdout=sample_trivy_json,
        stderr="",
    )

    service = TrivyScannerService()
    result = service.scan_image("python:3.12-slim")

    assert result.status == ScanStatus.COMPLETED
    assert result.summary.total == 5
    assert service.repository.get(result.scan_id) is not None

    # Verify subprocess argument construction
    args, kwargs = mock_subproc.call_args
    cmd_list = args[0]
    assert cmd_list[0] == service.settings.trivy_binary_path
    assert cmd_list[1] == "image"
    assert "--format" in cmd_list
    assert "json" in cmd_list
    assert "--cache-dir" in cmd_list
    assert "python:3.12-slim" in cmd_list
    assert kwargs.get("shell") is False


@patch("subprocess.run")
def test_scanner_service_missing_executable(mock_subproc: MagicMock) -> None:
    """Verify FileNotFoundError generates a failed scan record and raises ScannerNotInstalledError."""
    mock_subproc.side_effect = FileNotFoundError("Executable not found")

    service = TrivyScannerService()
    with pytest.raises(ScannerNotInstalledError):
        service.scan_image("python:3.12-slim")


@patch("subprocess.run")
def test_scanner_service_timeout(mock_subproc: MagicMock) -> None:
    """Verify subprocess timeout generates a failed scan record and raises ScannerTimeoutError."""
    mock_subproc.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=120)

    service = TrivyScannerService()
    with pytest.raises(ScannerTimeoutError):
        service.scan_image("python:3.12-slim")


@patch("subprocess.run")
def test_scanner_service_non_zero_exit(mock_subproc: MagicMock) -> None:
    """Verify non-zero return code generates a failed scan record and raises ScannerExecutionError."""
    mock_subproc.return_value = subprocess.CompletedProcess(
        args=["trivy"],
        returncode=1,
        stdout="",
        stderr="Failed to download vulnerability DB",
    )

    service = TrivyScannerService()
    with pytest.raises(ScannerExecutionError):
        service.scan_image("python:3.12-slim")


# ---------------------------------------------------------------------------
# API Endpoint Integration Tests (Mocked)
# ---------------------------------------------------------------------------


def test_api_get_approved_targets(client: TestClient) -> None:
    """Validate GET /api/v1/scans/targets lists approved images."""
    response = client.get("/api/v1/scans/targets")
    assert response.status_code == 200
    data = response.json()
    assert "allowed_targets" in data
    assert "python:3.12-slim" in data["allowed_targets"]
    assert data["total"] >= 1


@patch("subprocess.run")
def test_api_post_scan_image_success(
    mock_subproc: MagicMock,
    client: TestClient,
    sample_trivy_json: str,
) -> None:
    """Validate POST /api/v1/scans/image returns HTTP 200 with structured findings."""
    mock_subproc.return_value = subprocess.CompletedProcess(
        args=["trivy"],
        returncode=0,
        stdout=sample_trivy_json,
        stderr="",
    )

    response = client.post("/api/v1/scans/image", json={"image_name": "python:3.12-slim"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["target_image"] == "python:3.12-slim"
    assert data["summary"]["total"] == 5
    assert len(data["vulnerabilities"]) == 5

    # Verify retrieval endpoint works for the returned scan_id
    scan_id = data["scan_id"]
    get_res = client.get(f"/api/v1/scans/{scan_id}")
    assert get_res.status_code == 200
    assert get_res.json()["scan_id"] == scan_id


def test_api_post_scan_unauthorized_image_returns_400(client: TestClient) -> None:
    """Validate POST /api/v1/scans/image returns 400 for unapproved image."""
    response = client.post("/api/v1/scans/image", json={"image_name": "attacker/custom:latest"})
    assert response.status_code == 400
    assert "not authorized" in response.json()["detail"]


@patch("subprocess.run")
def test_api_post_scan_missing_scanner_returns_503(
    mock_subproc: MagicMock,
    client: TestClient,
) -> None:
    """Validate POST /api/v1/scans/image returns 503 when Trivy is not installed."""
    mock_subproc.side_effect = FileNotFoundError("Executable not found")
    response = client.post("/api/v1/scans/image", json={"image_name": "python:3.12-slim"})
    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"]


@patch("subprocess.run")
def test_api_post_scan_timeout_returns_504(
    mock_subproc: MagicMock,
    client: TestClient,
) -> None:
    """Validate POST /api/v1/scans/image returns 504 when scan times out."""
    mock_subproc.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=120)
    response = client.post("/api/v1/scans/image", json={"image_name": "python:3.12-slim"})
    assert response.status_code == 504
    assert "timed out" in response.json()["detail"]


@patch("subprocess.run")
def test_api_post_scan_execution_failure_returns_502(
    mock_subproc: MagicMock,
    client: TestClient,
) -> None:
    """Validate POST /api/v1/scans/image returns 502 when scanner exits with error code."""
    mock_subproc.return_value = subprocess.CompletedProcess(
        args=["trivy"],
        returncode=2,
        stdout="",
        stderr="Fatal error initializing cache",
    )
    response = client.post("/api/v1/scans/image", json={"image_name": "python:3.12-slim"})
    assert response.status_code == 502
    assert "execution failed" in response.json()["detail"]


def test_api_get_scan_not_found_returns_404(client: TestClient) -> None:
    """Validate GET /api/v1/scans/{scan_id} returns 404 for unknown ID."""
    response = client.get("/api/v1/scans/non-existent-scan-id")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]

def test_parse_trivy_finding_includes_risk_details():
    import json

    from backend.app.services.trivy_parser import parse_trivy_json

    raw_output = json.dumps({
        "Results": [
            {
                "Target": "test-image",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-12345",
                        "PkgName": "test-package",
                        "InstalledVersion": "1.0",
                        "Severity": "CRITICAL",
                    }
                ],
            }
        ]
    })

    result = parse_trivy_json(
        raw_output=raw_output,
        scan_id="test-scan",
        target_image="test-image",
        duration_seconds=1.0,
    )

    finding = result.vulnerabilities[0]

    assert finding.risk_score == 9.0
    
    assert finding.remediation_guidance == (
    "Address immediately; investigate mitigations and "
    "monitor vendor advisories."
    )

def test_parse_trivy_finding_includes_fixed_version_guidance():
    import json

    from backend.app.services.trivy_parser import parse_trivy_json

    raw_output = json.dumps({
        "Results": [
            {
                "Target": "test-image",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-56789",
                        "PkgName": "test-package",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.2.13",
                        "Severity": "CRITICAL",
                    }
                ],
            }
        ]
    })

    result = parse_trivy_json(
        raw_output=raw_output,
        scan_id="test-fixed-version",
        target_image="test-image",
        duration_seconds=1.0,
    )

    finding = result.vulnerabilities[0]

    assert finding.fixed_version == "1.2.13"
    assert "Upgrade to version 1.2.13." in finding.remediation_guidance
    assert "Address immediately" in finding.remediation_guidance
