"""
Guide: How to connect your RAG application to rag-sec for scanning
"""

from rag_sec.core.models import TargetConfig, TargetType
from rag_sec.core.connector import LangChainConnector, LlamaIndexConnector, HTTPRAGConnector, LocalPythonRAGConnector
from rag_sec.core.runner import SecurityRunner

# =====================================================================
# Option 1: Scanning a LangChain Pipeline (Chain / Runnable / Retriever)
# =====================================================================
def scan_langchain_example(your_langchain_chain):
    config = TargetConfig(name="My LangChain Application", target_type=TargetType.LANGCHAIN)
    
    # Pass your LangChain chain instance directly
    connector = LangChainConnector(config=config, chain_or_runnable=your_langchain_chain)
    
    runner = SecurityRunner(connector)
    report = runner.execute_scan()
    print(f"LangChain Scan Completed! Risk Score: {report.risk_score}/10.0")
    return report

# =====================================================================
# Option 2: Scanning a LlamaIndex Pipeline (QueryEngine / Index)
# =====================================================================
def scan_llamaindex_example(your_llama_query_engine):
    config = TargetConfig(name="My LlamaIndex Application", target_type=TargetType.LLAMA_INDEX)
    
    # Pass your LlamaIndex query engine instance directly
    connector = LlamaIndexConnector(config=config, query_engine=your_llama_query_engine)
    
    runner = SecurityRunner(connector)
    report = runner.execute_scan()
    print(f"LlamaIndex Scan Completed! Risk Score: {report.risk_score}/10.0")
    return report

# =====================================================================
# Option 3: Scanning an HTTP Endpoint / REST API Target
# =====================================================================
def scan_http_api_example(api_url="http://localhost:8000/api/query"):
    config = TargetConfig(
        name="My RAG REST Endpoint",
        target_type=TargetType.HTTP_ENDPOINT,
        endpoint_url=api_url,
        headers={"Authorization": "Bearer YOUR_API_TOKEN"}
    )
    
    connector = HTTPRAGConnector(config=config)
    runner = SecurityRunner(connector)
    report = runner.execute_scan()
    print(f"HTTP Endpoint Scan Completed! Risk Score: {report.risk_score}/10.0")
    return report

# =====================================================================
# Option 4: Scanning a Custom Python Query Function
# =====================================================================
def my_custom_rag_query(prompt: str, user_context: dict = None):
    # Your custom RAG retrieval and LLM logic here
    answer = f"Echoing response for prompt: {prompt}"
    retrieved_docs = [{"content": "Sample retrieved chunk", "metadata": {}}]
    return {"answer": answer, "retrieved_docs": retrieved_docs}

def scan_custom_python_function():
    config = TargetConfig(name="My Custom Python RAG", target_type=TargetType.LOCAL_PYTHON)
    connector = LocalPythonRAGConnector(config=config, query_fn=my_custom_rag_query)
    runner = SecurityRunner(connector)
    report = runner.execute_scan()
    print(f"Custom Python Scan Completed! Risk Score: {report.risk_score}/10.0")
    return report
