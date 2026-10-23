from typing import List, Dict, Any, Optional
from rag_app.retrieval.vector_store import VectorStore
from rag_app.ingestion.embedder import TextEmbedder
from rag_app.ingestion.chunker import Chunk

class RAGRetriever:
    """Retrieval system conducting targeted similarity search over VectorStore."""
    def __init__(self, vector_store: VectorStore, embedder: Optional[TextEmbedder] = None):
        self.vector_store = vector_store
        self.embedder = embedder or TextEmbedder()

    def retrieve(self, query: str, top_k: int = 1, user_context: Optional[Dict[str, Any]] = None, security_enabled: bool = False) -> List[Chunk]:
        query_vec = self.embedder.embed_text(query)
        
        metadata_filter = None
        if security_enabled and user_context:
            metadata_filter = {}
            if "tenant_id" in user_context:
                metadata_filter["tenant_id"] = user_context["tenant_id"]

        scored_results = self.vector_store.search(query_vec, top_k=5, metadata_filter=metadata_filter)
        
        # Keyword matching & vector score thresholding
        query_words = [w.lower() for w in query.split() if len(w) > 2]
        matching_chunks = []

        for chunk, score in scored_results:
            content_lower = chunk.content.lower()
            word_matches = sum(1 for w in query_words if w in content_lower)
            
            # Require minimum relevance score or keyword match
            if word_matches > 0 or score > 0.1:
                matching_chunks.append((chunk, score + (word_matches * 0.2)))

        matching_chunks.sort(key=lambda x: x[1], reverse=True)
        filtered_chunks = [c for c, _ in matching_chunks[:top_k]]

        if security_enabled and user_context and user_context.get("role") != "ADMIN":
            filtered_chunks = [c for c in filtered_chunks if c.metadata.get("role_required") != "ADMIN"]

        return filtered_chunks
