from abc import ABC, abstractmethod
from typing import List
import time
from rag_sec.core.connector import BaseRAGConnector
from rag_sec.core.models import EvaluatorResult, SecurityFinding, VulnerabilityCategory

class BaseEvaluator(ABC):
    def __init__(self, name: str, category: VulnerabilityCategory):
        self.name = name
        self.category = category

    @abstractmethod
    def run_tests(self, connector: BaseRAGConnector) -> EvaluatorResult:
        """Run evaluator tests against the RAG connector target and return results."""
        pass

    def create_result(self, findings: List[SecurityFinding], tests_run: int, passed_tests: int, failed_tests: int, duration: float) -> EvaluatorResult:
        return EvaluatorResult(
            evaluator_name=self.name,
            category=self.category,
            findings=findings,
            tests_run=tests_run,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            execution_time_seconds=round(duration, 3)
        )
