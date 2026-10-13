import re
from collections import defaultdict
from backend.app.schemas.scans import SeverityLevel, VulnerabilityItem
class RiskPrioritizationEngine:
    """Prioritize detected vulnerabilities based on risk."""

    SEVERITY_SCORES = {
        SeverityLevel.CRITICAL: 9.0,
        SeverityLevel.HIGH: 7.0,
        SeverityLevel.MEDIUM: 4.5,
        SeverityLevel.LOW: 2.0,
        SeverityLevel.UNKNOWN: 1.0,
    }

    @staticmethod
    def get_severity_score(severity: SeverityLevel) -> float:
        """Return the base risk score for a vulnerability severity."""

        if not isinstance(severity, SeverityLevel):
            raise ValueError("Unsupported severity level")

        return RiskPrioritizationEngine.SEVERITY_SCORES[severity]

    @staticmethod
    def calculate_risk_score(
        vulnerability: VulnerabilityItem,
    ) -> float:
        """Calculate the initial risk score for a vulnerability."""
        return RiskPrioritizationEngine.get_severity_score(
            vulnerability.severity
        )

    @staticmethod
    def rank_vulnerabilities(
        vulnerabilities: list[VulnerabilityItem],
    ) -> list[VulnerabilityItem]:
        """Rank vulnerabilities from highest to lowest risk."""
        return sorted(
        vulnerabilities,
        key=RiskPrioritizationEngine.calculate_risk_score,
        reverse=True,
    )

    @staticmethod
    def get_remediation_guidance(
        severity: SeverityLevel,
    ) -> str:
        """Return initial remediation guidance based on severity."""

        guidance = {
        SeverityLevel.CRITICAL: (
            "Address immediately; prioritize a fix or mitigation."
        ),
        SeverityLevel.HIGH: (
            "Remediate as a high priority."
        ),
        SeverityLevel.MEDIUM: (
            "Schedule remediation and assess exposure."
        ),
        SeverityLevel.LOW: (
            "Address during routine maintenance."
        ),
        SeverityLevel.UNKNOWN: (
            "Investigate the severity before prioritizing."
        ),
    }

        if not isinstance(severity, SeverityLevel):
            raise ValueError("Unsupported severity level")

        return guidance[severity]

    @staticmethod
    def group_by_cve(
        vulnerabilities: list[VulnerabilityItem],
    ) -> dict[str, list[VulnerabilityItem]]:
        """Group valid CVEs and preserve findings without valid CVE IDs."""
        grouped = defaultdict(list)
        unassociated_count = 0

        for vulnerability in vulnerabilities:
            vulnerability_id = vulnerability.vulnerability_id

            if re.fullmatch(r"CVE-\d{4}-\d+", vulnerability_id):
                grouped[vulnerability_id].append(vulnerability)
            else:
                unassociated_count += 1
                group_key = f"UNASSOCIATED-{unassociated_count}"
                grouped[group_key].append(vulnerability)

        return dict(grouped)