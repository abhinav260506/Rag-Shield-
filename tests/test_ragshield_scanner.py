import pytest
from rag_sec.core.models import TargetConfig, TargetType
from rag_sec.core.connector import LocalPythonRAGConnector
from scanner.engine import ScannerEngine
from rag_app.retrieval.vector_store import VectorStore
from rag_app.retrieval.retriever import RAGRetriever
from rag_app.generation.llm import LLMGenerator
from rag_app.ingestion.chunker import Chunk

def test_ragshield_audit_engine_execution():
    vector_store = VectorStore()
    retriever = RAGRetriever(vector_store)
    
    def mock_query(prompt, context):
        chunks = retriever.retrieve(prompt, top_k=3, user_context=context, security_enabled=False)
        gen = LLMGenerator(security_enabled=False)
        ans = gen.generate_response(prompt, chunks, user_context=context)
        return {"answer": ans, "retrieved_docs": [{"content": c.content, "metadata": c.metadata} for c in chunks]}

    def mock_ingest(content, metadata):
        c = Chunk(chunk_id=f"test-chunk-{len(vector_store.chunks)}", content=content, metadata=metadata or {})
        vector_store.add_chunk(c)
        return True

    config = TargetConfig(name="RAGShield Test Target", target_type=TargetType.LOCAL_PYTHON)
    connector = LocalPythonRAGConnector(config=config, query_fn=mock_query, ingest_fn=mock_ingest)

    engine = ScannerEngine(connector)
    report = engine.execute_audit()

    assert "risk_score" in report
    assert "findings" in report
    assert report["total_findings"] >= 0
