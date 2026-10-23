import uuid
import datetime
from typing import List, Optional
from rag_sec.core.connector import BaseRAGConnector
from rag_sec.core.models import ScanReport, EvaluatorResult, Severity, SecurityFinding
from rag_sec.evaluators.document_poisoning import DocumentPoisoningEvaluator
from rag_sec.evaluators.indirect_prompt_injection import IndirectPromptInjectionEvaluator
from rag_sec.evaluators.unauthorized_retrieval import UnauthorizedRetrievalEvaluator
from rag_sec.evaluators.data_leakage import DataLeakageEvaluator
from rag_sec.evaluators.retrieval_manipulation import RetrievalManipulationEvaluator

class SecurityRunner:
    def __init__(self, connector: BaseRAGConnector):
        self.connector = connector
        self.evaluators = [
            DocumentPoisoningEvaluator(),
            IndirectPromptInjectionEvaluator(),
            UnauthorizedRetrievalEvaluator(),
            DataLeakageEvaluator(),
            RetrievalManipulationEvaluator()
        ]

    def execute_scan(self, scan_id: Optional[str] = None) -> ScanReport:
        scan_id = scan_id or f"scan-{uuid.uuid4().hex[:8]}"
        evaluator_results: List[EvaluatorResult] = []
        findings_by_severity = {s: 0 for s in Severity}
        total_findings = 0

        for evaluator in self.evaluators:
            res = evaluator.run_tests(self.connector)
            evaluator_results.append(res)
            for finding in res.findings:
                findings_by_severity[finding.severity] += 1
                total_findings += 1

        # Risk score calculation formula:
        # CRITICAL * 3.5 + HIGH * 2.0 + MEDIUM * 1.0 + LOW * 0.5 (Capped at 10.0)
        weighted_score = (
            findings_by_severity[Severity.CRITICAL] * 3.5 +
            findings_by_severity[Severity.HIGH] * 2.0 +
            findings_by_severity[Severity.MEDIUM] * 1.0 +
            findings_by_severity[Severity.LOW] * 0.5
        )
        risk_score = round(min(10.0, weighted_score), 1)

        return ScanReport(
            scan_id=scan_id,
            target_name=self.connector.config.name,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            status="COMPLETED",
            total_findings=total_findings,
            findings_by_severity=findings_by_severity,
            evaluator_results=evaluator_results,
            risk_score=risk_score
        )
