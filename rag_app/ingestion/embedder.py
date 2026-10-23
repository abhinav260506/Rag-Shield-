import math
import re
from typing import List

class TextEmbedder:
    """Vector Embedding engine generating normalized numerical vector representations."""
    def __init__(self, vector_dim: int = 128):
        self.vector_dim = vector_dim

    def embed_text(self, text: str) -> List[float]:
        words = re.findall(r'\w+', text.lower())
        vec = [0.0] * self.vector_dim
        for word in words:
            idx = sum(ord(c) for c in word) % self.vector_dim
            vec[idx] += 1.0
        
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec
