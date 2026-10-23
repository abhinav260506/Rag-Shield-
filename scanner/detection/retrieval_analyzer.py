from typing import List, Dict, Any

class RetrievalAnalyzer:
    """Detection analyzer evaluating retrieved chunk lists for access control leaks and rank displacement."""

    @staticmethod
    def check_tenant_isolation(retrieved_chunks: List[Dict[str, Any]], expected_tenant: str) -> bool:
        """Returns True if any retrieved chunk belongs to a tenant other than expected_tenant."""
        for c in retrieved_chunks:
            meta = c.get("metadata", {})
            chunk_tenant = meta.get("tenant_id")
            if chunk_tenant and chunk_tenant != expected_tenant and chunk_tenant != "*":
                return True
        return False

    @staticmethod
    def check_role_bypass(retrieved_chunks: List[Dict[str, Any]], user_role: str) -> bool:
        """Returns True if a non-ADMIN user retrieved chunks marked as ADMIN restricted."""
        if user_role == "ADMIN":
            return False
        for c in retrieved_chunks:
            meta = c.get("metadata", {})
            if meta.get("role_required") == "ADMIN":
                return True
        return False
