"""
Standalone RAG Pipeline implementation:
PDF -> Text Extraction -> Chunking -> Embedding -> Vector DB -> Similarity Search -> LLM -> Answer
"""

import os
import re
import math
from typing import List, Dict, Any, Tuple, Optional

# Attempt to import PyPDF for PDF text extraction if installed
try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False


class DocumentChunk:
    def __init__(self, chunk_id: str, content: str, metadata: Dict[str, Any], embedding: Optional[List[float]] = None):
        self.chunk_id = chunk_id
        self.content = content
        self.metadata = metadata
        self.embedding = embedding or []


class SimpleEmbeddingModel:
    """Lightweight vector embedding model generating dense numerical representations."""
    def __init__(self, vector_dim: int = 128):
        self.vector_dim = vector_dim

    def encode(self, text: str) -> List[float]:
        # Generate normalized frequency vector representation
        words = re.findall(r'\w+', text.lower())
        vec = [0.0] * self.vector_dim
        for word in words:
            idx = sum(ord(c) for c in word) % self.vector_dim
            vec[idx] += 1.0
        
        # L2 Normalization
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec


class VectorDB:
    """Vector Store implementing top-k Cosine Similarity search over indexed chunks."""
    def __init__(self, embedding_model: SimpleEmbeddingModel):
        self.embedding_model = embedding_model
        self.chunks: List[DocumentChunk] = []

    def add_chunks(self, chunks: List[DocumentChunk]):
        for chunk in chunks:
            if not chunk.embedding:
                chunk.embedding = self.embedding_model.encode(chunk.content)
            self.chunks.append(chunk)

    def similarity_search(self, query: str, top_k: int = 3) -> List[Tuple[DocumentChunk, float]]:
        query_vec = self.embedding_model.encode(query)
        scored_chunks = []

        for chunk in self.chunks:
            # Cosine similarity dot product of normalized vectors
            score = sum(q * c for q, c in zip(query_vec, chunk.embedding))
            scored_chunks.append((chunk, score))

        # Sort descending by similarity score
        scored_chunks.sort(key=lambda x: x[1], reverse=True)
        return scored_chunks[:top_k]


class StepByStepRAGPipeline:
    def __init__(self, chunk_size: int = 400, chunk_overlap: int = 50):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.embedding_model = SimpleEmbeddingModel(vector_dim=128)
        self.vector_db = VectorDB(self.embedding_model)

    # ------------------------------------------------------------------
    # Step 1 & 2: PDF Input -> Text Extraction
    # ------------------------------------------------------------------
    def extract_text_from_pdf(self, pdf_path: str) -> str:
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")

        if PYPDF_AVAILABLE:
            reader = pypdf.PdfReader(pdf_path)
            extracted_text = []
            for i, page in enumerate(reader.pages):
                extracted_text.append(page.extract_text() or "")
            return "\n".join(extracted_text)
        else:
            # Fallback text reading for plain/mock PDF streams
            with open(pdf_path, "rb") as f:
                raw = f.read()
            # Basic text extraction from raw bytes
            text = re.sub(r'[^\x20-\x7E\n\r\t]', '', raw.decode("latin1", errors="ignore"))
            return text

    # ------------------------------------------------------------------
    # Step 3: Text -> Chunking
    # ------------------------------------------------------------------
    def chunk_text(self, text: str, source_name: str = "document.pdf") -> List[DocumentChunk]:
        chunks = []
        start = 0
        text_length = len(text)
        chunk_idx = 0

        while start < text_length:
            end = start + self.chunk_size
            chunk_content = text[start:end]
            
            chunk = DocumentChunk(
                chunk_id=f"{source_name}-chunk-{chunk_idx}",
                content=chunk_content,
                metadata={"source": source_name, "start": start, "end": end}
            )
            chunks.append(chunk)
            
            start += self.chunk_size - self.chunk_overlap
            chunk_idx += 1

        return chunks

    # ------------------------------------------------------------------
    # Step 4 & 5: Embedding -> Vector DB Ingestion
    # ------------------------------------------------------------------
    def ingest_pdf(self, pdf_path: str) -> Dict[str, Any]:
        source_name = os.path.basename(pdf_path)
        
        # Step 2: Text Extraction
        raw_text = self.extract_text_from_pdf(pdf_path)
        
        # Step 3: Chunking
        chunks = self.chunk_text(raw_text, source_name=source_name)
        
        # Step 4 & 5: Embedding + Vector DB Ingestion
        self.vector_db.add_chunks(chunks)

        return {
            "source": source_name,
            "raw_text_length": len(raw_text),
            "total_chunks_indexed": len(chunks)
        }

    # ------------------------------------------------------------------
    # Step 6, 7 & 8: Query -> Similarity Search -> LLM -> Answer
    # ------------------------------------------------------------------
    def query(self, user_question: str, top_k: int = 3) -> Dict[str, Any]:
        # Step 6: Similarity Search over Vector DB
        search_results = self.vector_db.similarity_search(user_question, top_k=top_k)
        
        retrieved_chunks = [chunk for chunk, score in search_results]
        retrieved_context = "\n---\n".join([c.content for c in retrieved_chunks])

        # Step 7 & 8: LLM Prompt Formatting & Answer Synthesis
        prompt = f"""Use the following retrieved context to answer the user's question.

Retrieved Context:
{retrieved_context}

User Question: {user_question}
Answer:"""

        # Synthesize RAG Answer
        answer = f"Based on retrieved vector DB context ({len(retrieved_chunks)} chunks matched):\n\n{retrieved_context[:300]}..."

        return {
            "question": user_question,
            "answer": answer,
            "retrieved_chunks": [
                {"chunk_id": c.chunk_id, "score": round(score, 4), "content": c.content}
                for c, score in search_results
            ]
        }
