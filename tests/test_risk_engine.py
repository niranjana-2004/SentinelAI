import pytest
from backend.app.schemas.scans import SeverityLevel, VulnerabilityItem
from backend.app.services.risk_engine import RiskPrioritizationEngine

@pytest.mark.parametrize(
    ("severity", "expected_score"),
    [
        (SeverityLevel.CRITICAL, 9.0),
        (SeverityLevel.HIGH, 7.0),
        (SeverityLevel.MEDIUM, 4.5),
        (SeverityLevel.LOW, 2.0),
        (SeverityLevel.UNKNOWN, 1.0),
    ],
)
def test_severity_score(severity, expected_score):
    score = RiskPrioritizationEngine.get_severity_score(severity)

    assert score == expected_score

def test_invalid_severity_raises_value_error():
    with pytest.raises(ValueError, match="Unsupported severity level"):
        RiskPrioritizationEngine.get_severity_score("URGENT")

def test_group_by_cve_preserves_multiple_package_findings():
    findings = [
        VulnerabilityItem(
            vulnerability_id="CVE-2025-1001",
            package_name="package-A",
            installed_version="1.0",
            fixed_version="1.1",
            severity=SeverityLevel.HIGH,
            target="test-image",
        ),
        VulnerabilityItem(
            vulnerability_id="CVE-2025-1001",
            package_name="package-B",
            installed_version="2.0",
            fixed_version="2.1",
            severity=SeverityLevel.HIGH,
            target="test-image",
        ),
    ]

    grouped = RiskPrioritizationEngine.group_by_cve(findings)

    assert len(grouped) == 1
    assert len(grouped["CVE-2025-1001"]) == 2

    package_names = {
        finding.package_name
        for finding in grouped["CVE-2025-1001"]
    }
    assert package_names == {"package-A", "package-B"}

def test_group_by_cve_preserves_findings_without_ids():
    findings = [
        VulnerabilityItem(
            vulnerability_id="",
            package_name="package-A",
            installed_version="1.0",
            severity=SeverityLevel.HIGH,
            target="test-image",
        ),
        VulnerabilityItem(
            vulnerability_id="",
            package_name="package-B",
            installed_version="2.0",
            severity=SeverityLevel.MEDIUM,
            target="test-image",
        ),
    ]

    grouped = RiskPrioritizationEngine.group_by_cve(findings)

    total_grouped_findings = sum(
        len(group) for group in grouped.values()
    )

    assert total_grouped_findings == 2

def test_group_by_cve_preserves_malformed_ids():
    findings = [
        VulnerabilityItem(
            vulnerability_id="CVE-invalid",
            package_name="package-A",
            installed_version="1.0",
            severity=SeverityLevel.HIGH,
            target="test-image",
        ),
    ]

    grouped = RiskPrioritizationEngine.group_by_cve(findings)

    total_grouped_findings = sum(
        len(group) for group in grouped.values()
    )

    assert total_grouped_findings == 1
    assert "CVE-invalid" not in grouped

def test_calculate_risk_score():
    vulnerability = VulnerabilityItem(
        vulnerability_id="CVE-2024-12345",
        package_name="test-package",
        installed_version="1.0",
        severity=SeverityLevel.CRITICAL,
        target="test-image",
    )

    score = RiskPrioritizationEngine.calculate_risk_score(
        vulnerability
    )

    assert score == 9.0

def test_rank_vulnerabilities_highest_risk_first():
    findings = [
        VulnerabilityItem(
            vulnerability_id="CVE-2024-11111",
            package_name="low-package",
            installed_version="1.0",
            severity=SeverityLevel.LOW,
            target="test-image",
        ),
        VulnerabilityItem(
            vulnerability_id="CVE-2024-22222",
            package_name="critical-package",
            installed_version="1.0",
            severity=SeverityLevel.CRITICAL,
            target="test-image",
        ),
        VulnerabilityItem(
            vulnerability_id="CVE-2024-33333",
            package_name="high-package",
            installed_version="1.0",
            severity=SeverityLevel.HIGH,
            target="test-image",
        ),
    ]

    ranked = RiskPrioritizationEngine.rank_vulnerabilities(
        findings
    )

    assert [
        item.severity for item in ranked
    ] == [
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.LOW,
    ]

def test_get_remediation_guidance():
    assert (
        RiskPrioritizationEngine.get_remediation_guidance(
            SeverityLevel.CRITICAL
        )
        == "Address immediately; prioritize a fix or mitigation."
    )

    assert (
        RiskPrioritizationEngine.get_remediation_guidance(
            SeverityLevel.HIGH
        )
        == "Remediate as a high priority."
    )

    assert (
        RiskPrioritizationEngine.get_remediation_guidance(
            SeverityLevel.MEDIUM
        )
        == "Schedule remediation and assess exposure."
    )

    assert (
        RiskPrioritizationEngine.get_remediation_guidance(
            SeverityLevel.LOW
        )
        == "Address during routine maintenance."
    )

    assert (
        RiskPrioritizationEngine.get_remediation_guidance(
            SeverityLevel.UNKNOWN
        )
        == "Investigate the severity before prioritizing."
    )
