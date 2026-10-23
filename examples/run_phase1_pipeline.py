"""
Phase 1 Demonstration: Step-by-Step RAG Pipeline Execution
PDF -> Text Extraction -> Chunking -> Embedding -> Vector DB -> Similarity Search -> LLM -> Answer
"""

import os
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree
from rag_sec.pipeline.rag_pipeline import StepByStepRAGPipeline

console = Console()

def run_phase1_demo():
    console.print(Panel.fit(
        "[bold cyan]Phase 1: Step-by-Step RAG Pipeline[/bold cyan]\n"
        "[dim]PDF ➔ Text Extraction ➔ Chunking ➔ Embedding ➔ Vector DB ➔ Similarity Search ➔ LLM ➔ Answer[/dim]",
        border_style="cyan"
    ))

    # Create sample demo PDF/Text document
    sample_doc_path = "sample_knowledge.txt"
    sample_text = """
    RAG Security Framework Documentation 2026.
    
    1. Document Ingestion Security:
    All incoming documents (PDF, TXT, DOCX) must be sanitized to strip zero-width characters and hidden prompt injection payloads prior to embedding generation.
    
    2. Vector Store Isolation & Access Control:
    The vector database must enforce tenant-level isolation using metadata filters (tenant_id) during similarity search to prevent unauthorized retrieval across tenant boundaries.
    
    3. LLM Response Defense:
    RAG output generation must sanitize output text against Personally Identifiable Information (PII) including Social Security Numbers and API keys.
    """
    
    with open(sample_doc_path, "w", encoding="utf-8") as f:
        f.write(sample_text)

    # Initialize RAG Pipeline
    pipeline = StepByStepRAGPipeline(chunk_size=200, chunk_overlap=30)

    # Step 1 & 2: PDF / Document -> Text Extraction
    console.print("\n[bold yellow]Step 1 & 2: Document Input ➔ Text Extraction[/bold yellow]")
    extracted_text = pipeline.extract_text_from_pdf(sample_doc_path)
    console.print(f"Extracted [cyan]{len(extracted_text)} characters[/cyan] from {sample_doc_path}")

    # Step 3: Text -> Chunking
    console.print("\n[bold yellow]Step 3: Text ➔ Chunking[/bold yellow]")
    chunks = pipeline.chunk_text(extracted_text, source_name="sample_knowledge.pdf")
    console.print(f"Created [cyan]{len(chunks)} chunks[/cyan] (size: 200 chars, overlap: 30 chars)")

    # Step 4 & 5: Chunking -> Vector Embedding -> Vector DB
    console.print("\n[bold yellow]Step 4 & 5: Chunking ➔ Embedding ➔ Vector DB Ingestion[/bold yellow]")
    pipeline.vector_db.add_chunks(chunks)
    console.print(f"Successfully generated embeddings and indexed [green]{len(chunks)} vectors[/green] in Vector DB.")

    # Step 6: Similarity Search over Vector DB
    user_query = "How does vector database isolation prevent unauthorized access?"
    console.print(f"\n[bold yellow]Step 6: User Query ➔ Vector DB Similarity Search[/bold yellow]")
    console.print(f"User Query: [italic cyan]\"{user_query}\"[/italic cyan]")
    
    search_results = pipeline.vector_db.similarity_search(user_query, top_k=2)
    tree = Tree("[bold green]Top-K Similarity Results from Vector DB[/bold green]")
    for chunk, score in search_results:
        tree.add(f"Chunk ID: [cyan]{chunk.chunk_id}[/cyan] (Similarity Score: [magenta]{score:.4f}[/magenta])\nContent: [dim]{chunk.content.strip()[:120]}...[/dim]")
    console.print(tree)

    # Step 7 & 8: Context -> LLM Prompt -> Answer
    console.print("\n[bold yellow]Step 7 & 8: Retrieved Context ➔ LLM Prompt ➔ Final Answer[/bold yellow]")
    res = pipeline.query(user_query, top_k=2)
    
    console.print(Panel(
        f"[bold green]LLM Answer Output:[/bold green]\n{res['answer']}",
        title="Final Answer",
        border_style="green"
    ))

if __name__ == "__main__":
    run_phase1_demo()
