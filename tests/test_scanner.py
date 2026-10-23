import pytest
from rag_sec.core.models import TargetConfig, TargetType, Severity
from rag_sec.core.connector import LocalPythonRAGConnector
from rag_sec.core.runner import SecurityRunner
from examples.mock_rag_target import get_mock_rag_target

def test_vulnerable_rag_pipeline_scan():
    # Test scan against unguarded mock RAG pipeline
    mock_app = get_mock_rag_target(security_enabled=False)
    config = TargetConfig(name="Vulnerable Test RAG", target_type=TargetType.LOCAL_PYTHON)
    connector = LocalPythonRAGConnector(config=config, query_fn=mock_app.query, ingest_fn=mock_app.ingest)
    
    runner = SecurityRunner(connector)
    report = runner.execute_scan()

    assert report.total_findings > 0
    assert report.risk_score > 0.0
    assert report.status == "COMPLETED"

def test_secured_rag_pipeline_scan():
    # Test scan against guarded mock RAG pipeline
    mock_app_vuln = get_mock_rag_target(security_enabled=False)
    config_vuln = TargetConfig(name="Vulnerable Test RAG", target_type=TargetType.LOCAL_PYTHON)
    connector_vuln = LocalPythonRAGConnector(config=config_vuln, query_fn=mock_app_vuln.query, ingest_fn=mock_app_vuln.ingest)
    report_vuln = SecurityRunner(connector_vuln).execute_scan()

    mock_app_sec = get_mock_rag_target(security_enabled=True)
    config_sec = TargetConfig(name="Secured Test RAG", target_type=TargetType.LOCAL_PYTHON)
    connector_sec = LocalPythonRAGConnector(config=config_sec, query_fn=mock_app_sec.query, ingest_fn=mock_app_sec.ingest)
    report_sec = SecurityRunner(connector_sec).execute_scan()

    # Secured pipeline must have a lower overall risk score than vulnerable pipeline
    assert report_sec.risk_score < report_vuln.risk_score
    assert report_sec.total_findings < report_vuln.total_findings
