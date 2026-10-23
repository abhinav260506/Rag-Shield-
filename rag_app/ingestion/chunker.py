from typing import List, Dict, Any

class Chunk:
    def __init__(self, chunk_id: str, content: str, metadata: Dict[str, Any]):
        self.chunk_id = chunk_id
        self.content = content
        self.metadata = metadata
        self.embedding: List[float] = []

class TextChunker:
    """Splits raw document text into overlapping chunks."""
    def __init__(self, chunk_size: int = 400, chunk_overlap: int = 50):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def split_text(self, text: str, source_name: str = "doc") -> List[Chunk]:
        chunks = []
        start = 0
        text_len = len(text)
        idx = 0

        while start < text_len:
            end = start + self.chunk_size
            chunk_text = text[start:end]
            chunk = Chunk(
                chunk_id=f"{source_name}-chunk-{idx}",
                content=chunk_text,
                metadata={"source": source_name, "start": start, "end": end}
            )
            chunks.append(chunk)
            start += self.chunk_size - self.chunk_overlap
            idx += 1

        return chunks
