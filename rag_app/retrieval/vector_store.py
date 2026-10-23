from typing import List, Tuple, Dict, Any, Optional
from rag_app.ingestion.chunker import Chunk
from rag_app.ingestion.embedder import TextEmbedder

class VectorStore:
    """Vector database holding indexed chunks and embeddings."""
    def __init__(self, embedder: Optional[TextEmbedder] = None):
        self.embedder = embedder or TextEmbedder()
        self.chunks: List[Chunk] = []

    def add_chunk(self, chunk: Chunk):
        if not chunk.embedding:
            chunk.embedding = self.embedder.embed_text(chunk.content)
        self.chunks.append(chunk)

    def add_chunks(self, chunks: List[Chunk]):
        for c in chunks:
            self.add_chunk(c)

    def search(self, query_vec: List[float], top_k: int = 3, metadata_filter: Optional[Dict[str, Any]] = None) -> List[Tuple[Chunk, float]]:
        scored = []
        for chunk in self.chunks:
            # Metadata ACL filtering check if provided
            if metadata_filter:
                match = True
                for k, v in metadata_filter.items():
                    if chunk.metadata.get(k) != v and v != "*":
                        match = False
                        break
                if not match:
                    continue

            # Cosine similarity dot product
            score = sum(q * c for q, c in zip(query_vec, chunk.embedding))
            scored.append((chunk, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]
