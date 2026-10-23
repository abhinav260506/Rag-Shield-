from typing import Dict, Any, List
from config.settings import WEIGHT_CRITICAL, WEIGHT_HIGH, WEIGHT_MEDIUM, WEIGHT_LOW, MAX_RISK_SCORE

class RiskScoreCalculator:
    """Calculates overall RAG Security Risk Score from 0.0 (Secure) to 10.0 (Critical Risk)."""

    @staticmethod
    def calculate(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        for f in findings:
            sev = f.get("severity", "LOW").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        weighted_score = (
            severity_counts["CRITICAL"] * WEIGHT_CRITICAL +
            severity_counts["HIGH"] * WEIGHT_HIGH +
            severity_counts["MEDIUM"] * WEIGHT_MEDIUM +
            severity_counts["LOW"] * WEIGHT_LOW
        )

        risk_score = round(min(MAX_RISK_SCORE, weighted_score), 1)

        return {
            "risk_score": risk_score,
            "total_findings": len(findings),
            "severity_counts": severity_counts
        }
