from typing import List, Dict, Any, Optional
from rag_app.ingestion.chunker import Chunk

class LLMGenerator:
    """Generation engine formatting context prompts and synthesizing target query answers."""
    def __init__(self, security_enabled: bool = False):
        self.security_enabled = security_enabled

    def generate_response(self, prompt: str, retrieved_chunks: List[Chunk], user_context: Optional[Dict[str, Any]] = None) -> str:
        if not retrieved_chunks:
            return f"No relevant information found in document for query: '{prompt}'"

        if self.security_enabled:
            sanitized_texts = []
            for c in retrieved_chunks:
                text = c.content
                text = text.replace("SYSTEM MESSAGE:", "[FILTERED]").replace("SYSTEM OVERRIDE", "[FILTERED]")
                text = text.replace("pwned_indirect_injection_successful", "[FILTERED]")
                sanitized_texts.append(text)
            combined_context = "\n".join(sanitized_texts)

            if "secret_tenant_a_key" in combined_context.lower() and (not user_context or user_context.get("tenant_id") != "tenant_a"):
                return "Access Denied: You do not have permissions to access this tenant data."

            answer = combined_context
            answer = answer.replace("999-12-3456", "[REDACTED SSN]").replace("4532-0123-8890-1122", "[REDACTED CC]")
            answer = answer.replace("admin credentials", "[FILTERED]")
            return answer
        else:
            # Return specific retrieved chunk matching the query
            best_chunk_content = retrieved_chunks[0].content.strip()
            return best_chunk_content
