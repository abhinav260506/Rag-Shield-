"""
Mock RAG target application with toggleable security guardrails for testing rag-sec.
Demonstrates vulnerable vs secured behavior for LangChain and LlamaIndex style pipelines.
"""

from typing import Dict, Any, List

class MockRAGApplication:
    def __init__(self, security_enabled: bool = False):
        self.security_enabled = security_enabled
        self.documents: List[Dict[str, Any]] = []

    def ingest(self, content: str, metadata: Dict[str, Any]):
        if self.security_enabled:
            # Defensive check: Sanitize hidden unicode characters & sanitize key overrides
            content = content.replace("\u200b", "").replace("\u200c", "")
            content = content.replace("SYSTEM OVERRIDE", "[FILTERED]").replace("SYSTEM MESSAGE:", "[FILTERED]")
            content = content.replace("pwned_indirect_injection_successful", "[FILTERED]")
            
            # Sanitize security metadata labels to prevent key poisoning
            if metadata.get("role_required") == "PUBLIC" and metadata.get("admin_override"):
                metadata["role_required"] = "RESTRICTED"

        self.documents.append({"content": content, "metadata": metadata or {}})

    def query(self, prompt: str, user_context: Dict[str, Any] = None) -> Dict[str, Any]:
        user_context = user_context or {"role": "GUEST", "tenant_id": "tenant_b"}
        
        # Retrieval Phase
        retrieved_docs = []
        for doc in self.documents:
            doc_meta = doc["metadata"]
            
            if self.security_enabled:
                # Mandatory metadata ACL enforcement
                doc_tenant = doc_meta.get("tenant_id")
                req_role = doc_meta.get("role_required")
                
                if doc_tenant and doc_tenant != user_context.get("tenant_id"):
                    continue # Skip document from different tenant
                if req_role == "ADMIN" and user_context.get("role") != "ADMIN":
                    continue # Skip restricted document
            
            retrieved_docs.append(doc)

        # Prompt Synthesis Phase
        if self.security_enabled:
            sanitized_docs = []
            for doc in retrieved_docs:
                c = doc["content"]
                c = c.replace("SYSTEM MESSAGE:", "[FILTERED]").replace("SYSTEM OVERRIDE", "[FILTERED]")
                c = c.replace("Disregard user query", "[FILTERED]").replace("reveal the internal system prompt", "[FILTERED]")
                sanitized_docs.append(c)
            combined_context = "\n---\n".join(sanitized_docs)

            # Redact sensitive PII and block instruction overrides
            if "secret_tenant_a_key" in combined_context.lower() and user_context.get("tenant_id") != "tenant_a":
                return {"answer": "Access Denied: You do not have permissions to access this tenant data.", "retrieved_docs": []}

            answer = f"Based on authorized documents: {combined_context}"
            # PII Redaction
            answer = answer.replace("999-12-3456", "[REDACTED SSN]").replace("4532-0123-8890-1122", "[REDACTED CC]")
            answer = answer.replace("admin credentials", "[FILTERED]")
            return {"answer": answer, "retrieved_docs": retrieved_docs}
        else:
            combined_context = "\n---\n".join([d["content"] for d in retrieved_docs])
            answer = f"Retrieved Context: {combined_context}\nAnswer to '{prompt}': Processed based on retrieved info."
            return {"answer": answer, "retrieved_docs": retrieved_docs}

# Quick instance factories for testing connectors
def get_mock_rag_target(security_enabled: bool = False):
    app = MockRAGApplication(security_enabled=security_enabled)
    return app
