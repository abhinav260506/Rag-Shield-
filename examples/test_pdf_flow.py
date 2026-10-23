import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from rag_app.ingestion.loader import DocumentLoader
from rag_app.ingestion.chunker import TextChunker
from rag_app.ingestion.embedder import TextEmbedder
from rag_app.retrieval.vector_store import VectorStore
from rag_app.retrieval.retriever import RAGRetriever
from rag_app.generation.llm import LLMGenerator

def test_document_upload_and_retrieval_flow():
    print("=== Step 1: Create Sample Document ===")
    sample_text = """
    ACME Corporation Security Policy 2026.
    Chapter 1: Remote Work Access.
    Employees accessing internal servers must connect via Multi-Factor Authentication (MFA) and VPN.
    
    Chapter 2: Data Encryption Guidelines.
    All customer databases must be encrypted at rest using AES-256 encryption algorithm.
    The primary database backup is stored in AWS US-East-1 region.
    """
    doc_filename = "acme_policy.txt"
    with open(doc_filename, "w", encoding="utf-8") as f:
        f.write(sample_text)
    print(f"Sample file created: {doc_filename}")

    print("\n=== Step 2: Document Processing & Vector DB Storage ===")
    embedder = TextEmbedder()
    vector_store = VectorStore(embedder)
    chunker = TextChunker(chunk_size=200, chunk_overlap=30)
    
    # 1. Text Extraction
    text = DocumentLoader.load_text(doc_filename)
    print(f"Extracted {len(text)} characters from document.")

    # 2. Chunking
    chunks = chunker.split_text(text, source_name=doc_filename)
    print(f"Split document into {len(chunks)} chunks.")

    # 3. Embedding & Ingestion into Vector Store
    for c in chunks:
        c.metadata["tenant_id"] = "tenant_a"
        c.metadata["role_required"] = "USER"
        vector_store.add_chunk(c)

    print(f"Successfully embedded and stored {len(vector_store.chunks)} chunks in Vector DB!")

    print("\n=== Step 3: Query & Vector Similarity Search ===")
    retriever = RAGRetriever(vector_store, embedder)
    generator = LLMGenerator(security_enabled=False)

    user_query = "What encryption algorithm is required for customer databases?"
    print(f"User Query: '{user_query}'")

    # Perform Similarity Search
    retrieved_chunks = retriever.retrieve(user_query, top_k=2, user_context={"tenant_id": "tenant_a", "role": "USER"})
    
    print(f"\nRetrieved {len(retrieved_chunks)} relevant chunk(s) from Vector DB:")
    for idx, c in enumerate(retrieved_chunks):
        print(f"  Chunk [{idx+1}] ID: {c.chunk_id}")
        print(f"  Content: {c.content.strip()}")

    # Synthesize LLM Answer
    answer = generator.generate_response(user_query, retrieved_chunks, user_context={"tenant_id": "tenant_a", "role": "USER"})
    print("\n=== Step 4: Final Synthesized Answer ===")
    print(answer)

if __name__ == "__main__":
    test_document_upload_and_retrieval_flow()
