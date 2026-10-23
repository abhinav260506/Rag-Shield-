import uuid
import datetime
import os
import json
from typing import Dict, Any, List, Optional

from scanner.tests.document_poisoning import DocumentPoisoningTest
from scanner.tests.prompt_injection import IndirectPromptInjectionTest
from scanner.tests.unauthorized_retrieval import UnauthorizedRetrievalTest
from scanner.tests.data_leakage import DataLeakageTest
from scanner.tests.retrieval_manipulation import RetrievalManipulationTest
from scanner.scoring.risk_score import RiskScoreCalculator
from config.settings import REPORTS_DIR

class ScannerEngine:
    """RAGShield Security Scanner Engine executing all security test modules."""
    def __init__(self, connector):
        self.connector = connector
        self.test_modules = [
            DocumentPoisoningTest(connector),
            IndirectPromptInjectionTest(connector),
            UnauthorizedRetrievalTest(connector),
            DataLeakageTest(connector),
            RetrievalManipulationTest(connector)
        ]

    def execute_audit(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        scan_id = scan_id or f"scan-{uuid.uuid4().hex[:8]}"
        all_findings = []

        for test_module in self.test_modules:
            findings = test_module.run()
            all_findings.extend(findings)

        score_res = RiskScoreCalculator.calculate(all_findings)

        report = {
            "scan_id": scan_id,
            "target_name": self.connector.config.name,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "risk_score": score_res["risk_score"],
            "total_findings": score_res["total_findings"],
            "severity_counts": score_res["severity_counts"],
            "findings": all_findings
        }

        # Save to reports directory
        report_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        report["report_file"] = report_path
        return report
