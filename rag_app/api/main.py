from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from rag_app.ingestion.loader import DocumentLoader
from rag_app.ingestion.chunker import TextChunker, Chunk
from rag_app.ingestion.embedder import TextEmbedder
from rag_app.retrieval.vector_store import VectorStore
from rag_app.retrieval.retriever import RAGRetriever
from rag_app.generation.llm import LLMGenerator

app = FastAPI(title="RAG Application API", version="1.0.0")

# Shared Application State
embedder = TextEmbedder()
vector_store = VectorStore(embedder)
retriever = RAGRetriever(vector_store, embedder)
chunker = TextChunker()

class QueryRequest(BaseModel):
    prompt: str
    user_context: Optional[Dict[str, Any]] = {"role": "USER", "tenant_id": "tenant_a"}
    security_enabled: bool = False

@app.post("/ingest")
async def ingest_documents(
    files: List[UploadFile] = File(...),
    tenant_id: str = Form("tenant_a"),
    role_required: str = Form("USER")
):
    ingested_summary = []
    for file in files:
        content_bytes = await file.read()
        text = DocumentLoader.load_bytes(content_bytes, file.filename)
        
        chunks = chunker.split_text(text, source_name=file.filename)
        for c in chunks:
            c.metadata["tenant_id"] = tenant_id
            c.metadata["role_required"] = role_required
            vector_store.add_chunk(c)

        ingested_summary.append({"filename": file.filename, "chunks": len(chunks)})

    return {"status": "SUCCESS", "ingested": ingested_summary, "total_chunks": len(vector_store.chunks)}

@app.post("/query")
def query_rag(req: QueryRequest):
    chunks = retriever.retrieve(req.prompt, top_k=3, user_context=req.user_context, security_enabled=req.security_enabled)
    generator = LLMGenerator(security_enabled=req.security_enabled)
    answer = generator.generate_response(req.prompt, chunks, user_context=req.user_context)
    return {
        "answer": answer,
        "retrieved_chunks": [{"chunk_id": c.chunk_id, "content": c.content, "metadata": c.metadata} for c in chunks]
    }
