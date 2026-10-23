from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import requests
import json
from rag_sec.core.models import TargetConfig

class TargetResponse:
    def __init__(self, answer: str, retrieved_docs: Optional[List[Dict[str, Any]]] = None, raw: Optional[Any] = None):
        self.answer = answer
        self.retrieved_docs = retrieved_docs or []
        self.raw = raw

class BaseRAGConnector(ABC):
    def __init__(self, config: TargetConfig):
        self.config = config

    @abstractmethod
    def query(self, prompt: str, user_context: Optional[Dict[str, Any]] = None) -> TargetResponse:
        """Query the RAG pipeline with a user prompt and optional context (user role, tenant_id)."""
        pass

    @abstractmethod
    def ingest_document(self, document_text: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Attempt document ingestion into the target RAG document store / vector index."""
        pass


class HTTPRAGConnector(BaseRAGConnector):
    def query(self, prompt: str, user_context: Optional[Dict[str, Any]] = None) -> TargetResponse:
        url = self.config.endpoint_url
        if not url:
            raise ValueError("Endpoint URL is required for HTTPRAGConnector")

        payload = {
            "prompt": prompt,
            "user_context": user_context or self.config.user_context
        }
        
        try:
            resp = requests.post(url, json=payload, headers=self.config.headers, timeout=15)
            data = resp.json()
            answer = data.get("answer") or data.get("response") or data.get("result") or str(resp.text)
            retrieved_docs = data.get("retrieved_docs") or data.get("context") or []
            return TargetResponse(answer=answer, retrieved_docs=retrieved_docs, raw=data)
        except Exception as e:
            return TargetResponse(answer=f"Error querying HTTP target: {str(e)}", raw=str(e))

    def ingest_document(self, document_text: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        url = self.config.endpoint_url
        if not url:
            return False
        ingest_url = url.rstrip("/") + "/ingest"
        try:
            resp = requests.post(ingest_url, json={"content": document_text, "metadata": metadata or {}}, headers=self.config.headers, timeout=15)
            return resp.status_code in [200, 201]
        except Exception:
            return False


class LocalPythonRAGConnector(BaseRAGConnector):
    def __init__(self, config: TargetConfig, query_fn=None, ingest_fn=None):
        super().__init__(config)
        self.query_fn = query_fn
        self.ingest_fn = ingest_fn

    def query(self, prompt: str, user_context: Optional[Dict[str, Any]] = None) -> TargetResponse:
        if not self.query_fn:
            return TargetResponse(answer="No local Python query function provided.")
        try:
            res = self.query_fn(prompt, user_context or self.config.user_context)
            if isinstance(res, str):
                return TargetResponse(answer=res)
            elif isinstance(res, dict):
                return TargetResponse(answer=res.get("answer", ""), retrieved_docs=res.get("retrieved_docs", []), raw=res)
            elif hasattr(res, "answer"):
                return TargetResponse(answer=getattr(res, "answer"), retrieved_docs=getattr(res, "retrieved_docs", []), raw=res)
            return TargetResponse(answer=str(res), raw=res)
        except Exception as e:
            return TargetResponse(answer=f"Local function execution error: {str(e)}")

    def ingest_document(self, document_text: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        if not self.ingest_fn:
            return False
        try:
            self.ingest_fn(document_text, metadata or {})
            return True
        except Exception:
            return False


class LangChainConnector(BaseRAGConnector):
    """Connector for LangChain Runnable / Chain / Retriever targets."""
    def __init__(self, config: TargetConfig, chain_or_runnable=None, vector_store=None):
        super().__init__(config)
        self.chain = chain_or_runnable
        self.vector_store = vector_store

    def query(self, prompt: str, user_context: Optional[Dict[str, Any]] = None) -> TargetResponse:
        if not self.chain:
            return TargetResponse(answer="LangChain runnable/chain is not initialized.")
        try:
            # Flexible invocation for LangChain Runnable or Legacy Chain
            context = user_context or self.config.user_context
            input_data = {"query": prompt, "question": prompt, "input": prompt}
            if context:
                input_data["user_context"] = context
                input_data["user_role"] = context.get("role")
                input_data["tenant_id"] = context.get("tenant_id")

            if hasattr(self.chain, "invoke"):
                res = self.chain.invoke(input_data)
            elif hasattr(self.chain, "run"):
                res = self.chain.run(prompt)
            else:
                res = self.chain(input_data)

            if isinstance(res, str):
                return TargetResponse(answer=res)
            elif isinstance(res, dict):
                answer = res.get("result") or res.get("answer") or res.get("output") or str(res)
                source_docs = res.get("source_documents") or res.get("context") or []
                docs_formatted = []
                for doc in source_docs:
                    if hasattr(doc, "page_content"):
                        docs_formatted.append({"content": doc.page_content, "metadata": getattr(doc, "metadata", {})})
                    elif isinstance(doc, dict):
                        docs_formatted.append(doc)
                return TargetResponse(answer=answer, retrieved_docs=docs_formatted, raw=res)
            
            return TargetResponse(answer=str(res), raw=res)
        except Exception as e:
            return TargetResponse(answer=f"LangChain invocation error: {str(e)}")

    def ingest_document(self, document_text: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        if self.vector_store and hasattr(self.vector_store, "add_texts"):
            try:
                self.vector_store.add_texts(texts=[document_text], metadatas=[metadata or {}])
                return True
            except Exception:
                return False
        return False


class LlamaIndexConnector(BaseRAGConnector):
    """Connector for LlamaIndex QueryEngine / Index targets."""
    def __init__(self, config: TargetConfig, query_engine=None, index=None):
        super().__init__(config)
        self.query_engine = query_engine
        self.index = index

    def query(self, prompt: str, user_context: Optional[Dict[str, Any]] = None) -> TargetResponse:
        if not self.query_engine:
            return TargetResponse(answer="LlamaIndex query engine is not initialized.")
        try:
            res = self.query_engine.query(prompt)
            answer = str(res)
            source_nodes = getattr(res, "source_nodes", [])
            docs_formatted = []
            for node in source_nodes:
                node_obj = getattr(node, "node", node)
                text = getattr(node_obj, "text", str(node_obj))
                metadata = getattr(node_obj, "metadata", {})
                docs_formatted.append({"content": text, "metadata": metadata, "score": getattr(node, "score", None)})
            return TargetResponse(answer=answer, retrieved_docs=docs_formatted, raw=res)
        except Exception as e:
            return TargetResponse(answer=f"LlamaIndex query error: {str(e)}")

    def ingest_document(self, document_text: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        if self.index and hasattr(self.index, "insert"):
            try:
                # Basic node or document creation fallback
                from llama_index.core import Document
                doc = Document(text=document_text, extra_info=metadata or {})
                self.index.insert(doc)
                return True
            except Exception:
                return False
        return False
