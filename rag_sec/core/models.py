from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
import datetime

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityCategory(str, Enum):
    DOCUMENT_POISONING = "Document Poisoning"
    INDIRECT_PROMPT_INJECTION = "Indirect Prompt Injection"
    UNAUTHORIZED_RETRIEVAL = "Unauthorized Retrieval / Access Control"
    DATA_LEAKAGE = "Data Leakage / PII Exposure"
    RETRIEVAL_MANIPULATION = "Retrieval Manipulation / Embedding Collision"

class TargetType(str, Enum):
    LANGCHAIN = "langchain"
    LLAMA_INDEX = "llama_index"
    HTTP_ENDPOINT = "http_endpoint"
    LOCAL_PYTHON = "local_python"
    VECTOR_STORE = "vector_store"

class TargetConfig(BaseModel):
    name: str = Field(..., description="Target name or identifier")
    target_type: TargetType = Field(..., description="Type of RAG target")
    endpoint_url: Optional[str] = Field(None, description="URL for HTTP endpoint targets")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP Headers")
    user_context: Dict[str, Any] = Field(default_factory=dict, description="User role/tenant context for RBAC testing")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional target parameters")

class SecurityFinding(BaseModel):
    id: str = Field(..., description="Unique finding ID")
    category: VulnerabilityCategory
    severity: Severity
    title: str
    description: str
    impact: str
    remediation: str
    owasp_mapping: str = Field("OWASP Top 10 for LLM Applications", description="OWASP benchmark mapping")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Payloads, traces, responses leading to finding")

class EvaluatorResult(BaseModel):
    evaluator_name: str
    category: VulnerabilityCategory
    findings: List[SecurityFinding] = Field(default_factory=list)
    tests_run: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    execution_time_seconds: float = 0.0

class ScanReport(BaseModel):
    scan_id: str
    target_name: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    status: str = "COMPLETED"
    total_findings: int = 0
    findings_by_severity: Dict[Severity, int] = Field(default_factory=dict)
    evaluator_results: List[EvaluatorResult] = Field(default_factory=list)
    risk_score: float = Field(0.0, description="Overall risk score from 0.0 (Secure) to 10.0 (Critical Risk)")
