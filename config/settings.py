# RAGShield Configuration Settings

import os

PROJECT_NAME = "RAGShield"
VERSION = "1.0.0"

# Default Chunking & Embedding Settings
DEFAULT_CHUNK_SIZE = 400
DEFAULT_CHUNK_OVERLAP = 50
EMBEDDING_DIM = 128

# Security Scanner Weights for Risk Scoring
WEIGHT_CRITICAL = 3.5
WEIGHT_HIGH = 2.0
WEIGHT_MEDIUM = 1.0
WEIGHT_LOW = 0.5
MAX_RISK_SCORE = 10.0

# Reports Directory
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
