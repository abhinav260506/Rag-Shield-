# 🛡️ RAGShield: RAG Application Security Scanner & Evaluation Suite

**RAGShield** is an automated security audit framework designed to test, benchmark, and secure Retrieval-Augmented Generation (RAG) applications across all stages: document ingestion, vector database indexing, access-controlled retrieval, and LLM output generation.

---

## 📁 Repository Structure

```
RAGShield/
│
├── rag_app/
│   ├── ingestion/
│   │   ├── loader.py              # Document Loader (PDF, TXT, DOCX)
│   │   ├── chunker.py             # Recursive Text Chunker
│   │   └── embedder.py            # Dense Vector Embedder
│   │
│   ├── retrieval/
│   │   ├── vector_store.py        # Vector Store Indexing
│   │   └── retriever.py           # Similarity Search & ACL Retriever
│   │
│   ├── generation/
│   │   └── llm.py                 # Context Prompting & LLM Synthesizer
│   │
│   └── api/
│       └── main.py                # FastAPI REST Service for RAG Pipeline
│
├── scanner/
│   ├── engine.py                  # RAGShield Audit Engine Orchestrator
│   │
│   ├── tests/                     # 5 Security Evaluator Test Modules
│   │   ├── document_poisoning.py
│   │   ├── prompt_injection.py
│   │   ├── unauthorized_retrieval.py
│   │   ├── data_leakage.py
│   │   └── retrieval_manipulation.py
│   │
│   ├── detection/                 # Security Anomaly Detection Analyzers
│   │   ├── response_analyzer.py
│   │   └── retrieval_analyzer.py
│   │
│   └── scoring/
│       └── risk_score.py          # Risk Score Calculator (0.0 to 10.0)
│
├── rag_sec/                       # Core Security Evaluation Framework & CLI
│   ├── cli/
│   │   └── main.py                # CLI Entry Point
│   ├── core/                      # Models, Connectors, & Security Runner
│   ├── evaluators/                # Evaluator Modules
│   └── web/
│       └── app.py                 # Web UI Platform
│
├── dashboard/
│   └── app.py                     # Web App & Dashboard UI
│
├── reports/                       # Generated JSON Audit Reports
│
├── tests/                         # Unit & Integration Tests
│
├── config/
│   └── settings.py                # Project Settings & Constants
│
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## 🚀 Quick Start Guide

### 1. Clone the Repository

```bash
git clone https://github.com/abhinav260506/Rag-Shield-.git
cd Rag-Shield-
```

### 2. Set Up a Virtual Environment (Recommended)

```bash
# On Linux / macOS:
python3 -m venv venv
source venv/bin/activate

# On Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Test Suite

Verify your installation by running the test suite:

```bash
pytest
```

---

## 🖥️ Running the Application

### Option A: Web Dashboard UI

Launch the interactive RAGShield security dashboard:

```bash
python -m uvicorn dashboard.app:app --reload --port 8000
```

Open [http://localhost:8000](http://localhost:8000) in your browser. From the dashboard you can:
- **Upload & Embed Documents**: Test PDF and TXT document ingestion.
- **Query the RAG Pipeline**: Compare answers with and without security guardrails enabled.
- **Run Security Audit**: Trigger full automated vulnerability scans and view detailed remediation reports.

### Option B: Command Line Interface (CLI)

Run an audit directly from your terminal:

```bash
# Run security scan against sample mock target (vulnerable baseline)
python -m rag_sec.cli.main scan --mock

# Run security scan against guarded baseline
python -m rag_sec.cli.main scan --mock --guarded

# Run scan against an external HTTP RAG endpoint
python -m rag_sec.cli.main scan --url http://localhost:8000/api/rag/query
```

---

## 🛡️ Security Vulnerabilities Evaluated

RAGShield audits RAG systems against OWASP Top 10 for LLM Applications:

| Vulnerability Category | OWASP Mapping | Description |
|------------------------|---------------|-------------|
| **Document Poisoning** | LLM03 / LLM08 | Zero-width unicode character overlays and metadata label overrides. |
| **Indirect Prompt Injection** | LLM01 | Instruction hijacking via retrieved document context and wrapper tag escapes (`</context>`). |
| **Unauthorized Retrieval** | LLM08 | Cross-tenant data isolation breaches and role-based access control (RBAC) bypasses. |
| **Data Leakage** | LLM06 | Unredacted PII disclosure (SSNs, credit cards) and internal system prompt key exposure. |
| **Retrieval Manipulation** | LLM04 | Near-duplicate semantic noise flooding and context window displacement. |

---

## 📄 License

This project is licensed under the MIT License - see the `pyproject.toml` file for details.
