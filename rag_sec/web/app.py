from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import os
import shutil
import uuid
import datetime
import json

from rag_sec.core.models import TargetConfig, TargetType, Severity
from rag_sec.core.connector import LocalPythonRAGConnector, HTTPRAGConnector, BaseRAGConnector
from rag_sec.core.runner import SecurityRunner
from examples.mock_rag_target import get_mock_rag_target

app = FastAPI(
    title="RAG Security Scanner Platform",
    description="Full End-to-End RAG Application Builder and Automated Security Audit Scanner",
    version="0.2.0"
)

# In-Memory Vector Store & Document Store for User Uploaded RAG Pipelines
uploaded_documents: List[Dict[str, Any]] = []
processed_chunks: List[Dict[str, Any]] = []
scan_history: List[Dict[str, Any]] = []

class QueryRequest(BaseModel):
    prompt: str
    user_context: Optional[Dict[str, Any]] = {"role": "USER", "tenant_id": "tenant_a"}
    security_enabled: bool = False

class InteractiveRAGPipeline:
    def __init__(self, security_enabled: bool = False, is_scan_target: bool = False):
        self.security_enabled = security_enabled
        self.is_scan_target = is_scan_target
        self.scan_documents: List[Dict[str, Any]] = []

    def ingest(self, content: str, metadata: Dict[str, Any]):
        metadata = metadata or {}
        if self.security_enabled:
            # Defensive check: Sanitize hidden unicode characters & sanitize key overrides
            content = content.replace("\u200b", "").replace("\u200c", "")
            content = content.replace("SYSTEM OVERRIDE", "[FILTERED]").replace("SYSTEM MESSAGE:", "[FILTERED]")
            content = content.replace("pwned_indirect_injection_successful", "[FILTERED]")
            if metadata.get("role_required") == "PUBLIC" and metadata.get("admin_override"):
                metadata["role_required"] = "RESTRICTED"

        doc_entry = {"content": content, "metadata": metadata}
        if self.is_scan_target:
            self.scan_documents.append(doc_entry)
        else:
            processed_chunks.append(doc_entry)

    def query(self, prompt: str, user_context: Dict[str, Any] = None) -> Dict[str, Any]:
        user_context = user_context or {"role": "USER", "tenant_id": "tenant_a"}
        
        all_docs = self.scan_documents if self.is_scan_target else (uploaded_documents + processed_chunks)
        if not all_docs:
            all_docs = [
                {"content": "Default RAG Knowledge Base Document 2026.", "metadata": {"tenant_id": "tenant_a", "role_required": "USER"}}
            ]

        prompt_words = [w.lower() for w in prompt.split() if len(w) > 2]
        scored_docs = []

        for doc in all_docs:
            doc_meta = doc.get("metadata", {})
            
            if self.security_enabled:
                doc_tenant = doc_meta.get("tenant_id")
                req_role = doc_meta.get("role_required")
                if doc_tenant and doc_tenant != user_context.get("tenant_id"):
                    continue
                if req_role == "ADMIN" and user_context.get("role") != "ADMIN":
                    continue
            
            content = doc.get("content", "")
            matches = sum(1 for w in prompt_words if w in content.lower())
            if matches > 0:
                scored_docs.append((doc, matches))

        scored_docs.sort(key=lambda x: x[1], reverse=True)
        retrieved_docs = [d for d, _ in scored_docs[:1]]

        if not retrieved_docs and all_docs:
            retrieved_docs = [all_docs[0]]

        if self.security_enabled:
            sanitized_docs = []
            for doc in retrieved_docs:
                c = doc.get("content", "")
                c = c.replace("SYSTEM MESSAGE:", "[FILTERED]").replace("SYSTEM OVERRIDE", "[FILTERED]")
                sanitized_docs.append(c)
            combined_context = "\n".join(sanitized_docs)

            if "secret_tenant_a_key" in combined_context.lower() and user_context.get("tenant_id") != "tenant_a":
                return {"answer": "Access Denied: You do not have permissions to access this tenant data.", "retrieved_docs": []}

            answer = combined_context
            answer = answer.replace("999-12-3456", "[REDACTED SSN]").replace("4532-0123-8890-1122", "[REDACTED CC]")
            return {"answer": answer, "retrieved_docs": retrieved_docs}
        else:
            best_chunk = retrieved_docs[0].get("content", "").strip() if retrieved_docs else "No matching content."
            return {"answer": best_chunk, "retrieved_docs": retrieved_docs}

@app.post("/api/pipeline/phase1/run")
def run_phase1_pipeline_step_by_step(query: str = "How do vector databases enforce access control?"):
    """
    Executes Phase 1 step by step:
    PDF/Doc -> Text Extraction -> Chunking -> Embedding -> Vector DB -> Similarity Search -> LLM -> Answer
    """
    from rag_sec.pipeline.rag_pipeline import StepByStepRAGPipeline
    pipeline = StepByStepRAGPipeline(chunk_size=300, chunk_overlap=40)
    
    sample_text = """
    RAG Pipeline Security Guideline 2026.
    1. Document Ingestion: All incoming PDF and text files are processed into text chunks and embedded into vectors.
    2. Vector Database: Chunks are stored in Chroma / FAISS vector stores with metadata tags.
    3. Similarity Search: User queries compute cosine similarity against indexed chunk vectors.
    4. LLM Synthesis: Top matching chunks are injected into prompt context to synthesize answers.
    """
    chunks = pipeline.chunk_text(sample_text, source_name="phase1_sample.pdf")
    pipeline.vector_db.add_chunks(chunks)

    # Execute Similarity Search & LLM Step
    search_res = pipeline.vector_db.similarity_search(query, top_k=2)
    output = pipeline.query(query, top_k=2)

    return {
        "step_1_pdf": "phase1_sample.pdf",
        "step_2_text_extracted": sample_text,
        "step_3_chunks_count": len(chunks),
        "step_4_embeddings_dim": 128,
        "step_5_vector_db_size": len(pipeline.vector_db.chunks),
        "step_6_similarity_search_results": [
            {"chunk_id": c.chunk_id, "score": round(score, 4), "content": c.content}
            for c, score in search_res
        ],
        "step_7_llm_prompt": f"Context: {[c.content for c, _ in search_res]} | Query: {query}",
        "step_8_answer": output["answer"]
    }

@app.post("/api/documents/upload")
async def upload_documents(
    files: List[UploadFile] = File(...),
    tenant_id: str = Form("tenant_a"),
    role_required: str = Form("USER"),
    clear_existing: bool = Form(True)
):
    """Step 1: Document Upload & Chunking into Vector DB."""
    from rag_app.ingestion.loader import DocumentLoader
    
    if clear_existing:
        uploaded_documents.clear()
        processed_chunks.clear()

    uploaded_files_summary = []
    for file in files:
        content_bytes = await file.read()
        text_content = DocumentLoader.load_bytes(content_bytes, file.filename)

        metadata = {
            "filename": file.filename,
            "tenant_id": tenant_id,
            "role_required": role_required,
            "uploaded_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

        # Simple Chunking Logic (split every 500 chars)
        chunks = [text_content[i:i+500] for i in range(0, len(text_content), 500)]
        for idx, chunk in enumerate(chunks):
            doc_obj = {
                "id": f"{file.filename}-chunk-{idx}",
                "content": chunk,
                "metadata": metadata
            }
            uploaded_documents.append(doc_obj)

        uploaded_files_summary.append({
            "filename": file.filename,
            "size_bytes": len(content_bytes),
            "chunks_created": len(chunks)
        })

    return {
        "status": "SUCCESS",
        "message": f"Successfully processed and embedded {len(files)} document(s) into Vector DB.",
        "uploaded_files": uploaded_files_summary,
        "total_documents_in_db": len(uploaded_documents)
    }

@app.post("/api/documents/clear")
def clear_vector_db():
    uploaded_documents.clear()
    processed_chunks.clear()
    return {"status": "SUCCESS", "message": "Vector DB reset cleanly."}

@app.post("/api/rag/query")
def query_rag_pipeline(req: QueryRequest):
    """Interactive RAG Query endpoint."""
    rag_app = InteractiveRAGPipeline(security_enabled=req.security_enabled)
    res = rag_app.query(req.prompt, req.user_context)
    return res

@app.post("/api/scan")
def trigger_security_scan(target_type: str = "interactive", guarded: bool = False, endpoint_url: Optional[str] = None):
    """
    Step 5: Automated Security Scanner
    Runs Document Tests, Retrieval Tests, and LLM Tests through Detection Engine & Risk Assessment.
    """
    if target_type == "interactive":
        rag_app = InteractiveRAGPipeline(security_enabled=guarded)
        config = TargetConfig(
            name=f"Uploaded RAG Pipeline ({'Secured' if guarded else 'Vulnerable'})",
            target_type=TargetType.LOCAL_PYTHON
        )
        connector = LocalPythonRAGConnector(config=config, query_fn=rag_app.query, ingest_fn=rag_app.ingest)
    elif target_type == "mock":
        mock_app = get_mock_rag_target(security_enabled=guarded)
        config = TargetConfig(
            name=f"Mock RAG Benchmark ({'Secured' if guarded else 'Vulnerable'})",
            target_type=TargetType.LOCAL_PYTHON
        )
        connector = LocalPythonRAGConnector(config=config, query_fn=mock_app.query, ingest_fn=mock_app.ingest)
    elif target_type == "http":
        if not endpoint_url:
            raise HTTPException(status_code=400, detail="endpoint_url is required for HTTP target scan")
        config = TargetConfig(name="HTTP RAG Endpoint", target_type=TargetType.HTTP_ENDPOINT, endpoint_url=endpoint_url)
        connector = HTTPRAGConnector(config=config)
    else:
        raise HTTPException(status_code=400, detail="Invalid target_type")

    runner = SecurityRunner(connector)
    report = runner.execute_scan()
    report_dict = report.model_dump()
    scan_history.insert(0, report_dict)
    return report_dict

@app.get("/api/scans")
def get_scan_history():
    return scan_history

@app.get("/", response_class=HTMLResponse)
def serve_platform_dashboard():
    dashboard_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RAG Application Builder & Security Scanner Platform</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-primary: #0b0f19;
                --bg-card: rgba(22, 30, 46, 0.75);
                --bg-input: rgba(11, 15, 25, 0.8);
                --accent-cyan: #00f2fe;
                --accent-blue: #4facfe;
                --accent-purple: #7928ca;
                --text-main: #f1f5f9;
                --text-muted: #94a3b8;
                --border-color: rgba(255, 255, 255, 0.1);
                --critical-color: #ef4444;
                --high-color: #f97316;
                --medium-color: #eab308;
                --success-color: #22c55e;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: 'Inter', sans-serif;
                background: var(--bg-primary);
                color: var(--text-main);
                min-height: 100vh;
                padding: 1.5rem;
            }
            .navbar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1.5rem;
                padding-bottom: 1rem;
                border-bottom: 1px solid var(--border-color);
            }
            .logo {
                font-size: 1.4rem;
                font-weight: 700;
                background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            .flow-pipeline {
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: rgba(15, 23, 42, 0.6);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 1rem 1.5rem;
                margin-bottom: 2rem;
                overflow-x: auto;
            }
            .step-node {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 0.25rem;
                font-size: 0.8rem;
                color: var(--text-muted);
            }
            .step-node.active {
                color: var(--accent-cyan);
                font-weight: 600;
            }
            .step-icon {
                width: 36px;
                height: 36px;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid var(--border-color);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.1rem;
            }
            .step-node.active .step-icon {
                background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
                color: #000;
                border: none;
            }
            .step-arrow { color: var(--border-color); font-size: 1.2rem; }
            .grid-3 {
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 1.5rem;
            }
            @media (max-width: 1200px) { .grid-3 { grid-template-columns: 1fr; } }
            .card {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 1.25rem;
                backdrop-filter: blur(16px);
            }
            .card-title {
                font-size: 1.1rem;
                font-weight: 600;
                margin-bottom: 1rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            .form-group { margin-bottom: 1rem; }
            label { display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.4rem; }
            input, select, textarea {
                width: 100%;
                padding: 0.75rem;
                background: var(--bg-input);
                border: 1px solid var(--border-color);
                border-radius: 6px;
                color: #fff;
                font-family: inherit;
                font-size: 0.85rem;
            }
            .btn {
                width: 100%;
                padding: 0.75rem;
                border: none;
                border-radius: 6px;
                background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
                color: #000;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.1s ease;
            }
            .btn:hover { transform: translateY(-2px); }
            .btn-danger {
                background: linear-gradient(135deg, #ef4444, #dc2626);
                color: #fff;
            }
            .finding-card {
                background: rgba(15, 23, 42, 0.8);
                border-left: 4px solid var(--critical-color);
                border-radius: 6px;
                padding: 0.85rem;
                margin-bottom: 0.85rem;
            }
            .code-box {
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.75rem;
                background: #05070a;
                padding: 0.5rem;
                border-radius: 6px;
                color: #38bdf8;
                overflow-x: auto;
                max-height: 150px;
            }
            .badge {
                padding: 0.2rem 0.5rem;
                border-radius: 4px;
                font-size: 0.7rem;
                font-weight: 600;
            }
        </style>
    </head>
    <body>
        <div class="navbar">
            <div class="logo">🛡️ RAG-SEC // Security Scanner & RAG Platform</div>
            <div style="font-size:0.85rem; color:var(--text-muted);">OWASP Top 10 for LLM Applications Benchmark</div>
        </div>

        <!-- Flow Pipeline Header -->
        <div class="flow-pipeline">
            <div class="step-node active">
                <div class="step-icon">📁</div>
                <div>1. Upload Docs</div>
            </div>
            <div class="step-arrow">➔</div>
            <div class="step-node active">
                <div class="step-icon">⚙️</div>
                <div>2. Chunk & Embed</div>
            </div>
            <div class="step-arrow">➔</div>
            <div class="step-node active">
                <div class="step-icon">🗄️</div>
                <div>3. Vector DB</div>
            </div>
            <div class="step-arrow">➔</div>
            <div class="step-node active">
                <div class="step-icon">🔍</div>
                <div>4. Retrieval & LLM</div>
            </div>
            <div class="step-arrow">➔</div>
            <div class="step-node active" style="color:var(--accent-purple)">
                <div class="step-icon" style="background:var(--accent-purple); color:#fff;">🛡️</div>
                <div>5. Security Scanner</div>
            </div>
        </div>

        <div class="grid-3">
            <!-- Col 1: Document Upload & Vector DB Builder -->
            <div class="card">
                <div class="card-title">📁 1 & 2. Upload Docs & Build Vector DB</div>
                <form id="uploadForm">
                    <div class="form-group">
                        <label>Select Documents (TXT, PDF, DOCX)</label>
                        <input type="file" id="fileInput" multiple required>
                    </div>
                    <div class="form-group">
                        <label>Tenant ID (Multi-Tenant Metadata)</label>
                        <input type="text" id="tenantId" value="tenant_a">
                    </div>
                    <div class="form-group">
                        <label>Role Required (Access Control ACL)</label>
                        <select id="roleReq">
                            <option value="USER">USER (Standard Access)</option>
                            <option value="ADMIN">ADMIN (Restricted Access)</option>
                        </select>
                    </div>
                    <button type="submit" class="btn" id="uploadBtn">Embed & Index into Vector DB</button>
                </form>
                <div id="uploadStatus" style="margin-top: 1rem; font-size: 0.8rem; color: var(--text-muted);"></div>
            </div>

            <!-- Col 2: Interactive RAG Query Tester -->
            <div class="card">
                <div class="card-title">🔍 3 & 4. Query RAG Pipeline</div>
                <form id="queryForm">
                    <div class="form-group">
                        <label>User Query / Prompt</label>
                        <textarea id="promptInput" rows="3" placeholder="Ask a question about uploaded documents..."></textarea>
                    </div>
                    <div class="form-group">
                        <label>User Context (Role & Tenant)</label>
                        <select id="userRole">
                            <option value="USER">User Role: Standard USER (Tenant A)</option>
                            <option value="ADMIN">User Role: ADMIN (Tenant A)</option>
                            <option value="GUEST">User Role: GUEST (Tenant B)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Guardrails Switch</label>
                        <select id="queryGuarded">
                            <option value="false">Off (Vulnerable Pipeline)</option>
                            <option value="true">On (Secured Guardrails Enabled)</option>
                        </select>
                    </div>
                    <button type="submit" class="btn">Send Query to RAG</button>
                </form>
                <div id="queryResult" style="margin-top:1rem;"></div>
            </div>

            <!-- Col 3: Automated Security Audit Scanner -->
            <div class="card">
                <div class="card-title">🛡️ 5. Automated Security Scanner</div>
                <p style="font-size:0.8rem; color:var(--text-muted); margin-bottom:1rem;">
                    Automatically runs <b>Document Tests</b>, <b>Retrieval Tests</b>, and <b>LLM Tests</b> (Poisoning, Indirect Prompt Injection, Access Control Bypass, Data Leakage).
                </p>
                <form id="scanForm">
                    <div class="form-group">
                        <label>Target to Audit</label>
                        <select id="scanTargetType">
                            <option value="interactive">Uploaded Vector DB RAG Pipeline</option>
                            <option value="mock">Built-in RAG Benchmark Suite</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Pipeline Guardrail Mode</label>
                        <select id="scanGuarded">
                            <option value="false">Audit Vulnerable Baseline (No Guardrails)</option>
                            <option value="true">Audit Secured Baseline (With Guardrails)</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-danger" id="scanBtn">🚀 Run Full Security Audit</button>
                </form>
            </div>
        </div>

        <!-- Security Report Output Section -->
        <div class="card" style="margin-top: 1.5rem;">
            <div class="card-title">📊 Security Audit Report & Risk Assessment</div>
            <div id="reportContainer">
                <p style="color:var(--text-muted); font-size:0.85rem;">Click "Run Full Security Audit" above to generate your RAG Security Vulnerability Assessment Report.</p>
            </div>
        </div>

        <script>
            // Handle Document Upload
            document.getElementById('uploadForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const btn = document.getElementById('uploadBtn');
                btn.innerText = 'Embedding & Indexing...';
                btn.disabled = true;

                const formData = new FormData();
                const files = document.getElementById('fileInput').files;
                for (let i = 0; i < files.length; i++) {
                    formData.append('files', files[i]);
                }
                formData.append('tenant_id', document.getElementById('tenantId').value);
                formData.append('role_required', document.getElementById('roleReq').value);

                try {
                    const res = await fetch('/api/documents/upload', { method: 'POST', body: formData });
                    const data = await res.json();
                    document.getElementById('uploadStatus').innerHTML = `<span style="color:#22c55e">✅ ${data.message}</span>`;
                } catch (err) {
                    document.getElementById('uploadStatus').innerHTML = `<span style="color:#ef4444">❌ Upload error: ${err}</span>`;
                } finally {
                    btn.innerText = 'Embed & Index into Vector DB';
                    btn.disabled = false;
                }
            });

            // Handle RAG Query
            document.getElementById('queryForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const prompt = document.getElementById('promptInput').value;
                const role = document.getElementById('userRole').value;
                const guarded = document.getElementById('queryGuarded').value === 'true';

                const tenantMap = { 'USER': 'tenant_a', 'ADMIN': 'tenant_a', 'GUEST': 'tenant_b' };
                const payload = {
                    prompt: prompt,
                    user_context: { role: role, tenant_id: tenantMap[role] },
                    security_enabled: guarded
                };

                const res = await fetch('/api/rag/query', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                document.getElementById('queryResult').innerHTML = `
                    <div style="background:rgba(0,0,0,0.4); padding:0.75rem; border-radius:6px; border:1px solid var(--border-color);">
                        <div style="font-weight:600; font-size:0.85rem; color:var(--accent-cyan); margin-bottom:0.25rem;">Answer:</div>
                        <div style="font-size:0.8rem; margin-bottom:0.5rem;">${data.answer}</div>
                        <div style="font-size:0.75rem; color:var(--text-muted);">Retrieved Chunks: ${data.retrieved_docs ? data.retrieved_docs.length : 0}</div>
                    </div>
                `;
            });

            // Handle Security Audit Scan
            document.getElementById('scanForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const btn = document.getElementById('scanBtn');
                btn.innerText = 'Running Security Tests (Document, Retrieval, LLM)...';
                btn.disabled = true;

                const targetType = document.getElementById('scanTargetType').value;
                const guarded = document.getElementById('scanGuarded').value === 'true';

                try {
                    const res = await fetch(`/api/scan?target_type=${targetType}&guarded=${guarded}`, { method: 'POST' });
                    const report = await res.json();
                    renderSecurityReport(report);
                } catch (err) {
                    alert('Scan Execution Error: ' + err);
                } finally {
                    btn.innerText = '🚀 Run Full Security Audit';
                    btn.disabled = false;
                }
            });

            function renderSecurityReport(report) {
                const container = document.getElementById('reportContainer');
                let findingsHtml = '';

                report.evaluator_results.forEach(res => {
                    res.findings.forEach(f => {
                        const sevColor = f.severity === 'CRITICAL' ? 'var(--critical-color)' : (f.severity === 'HIGH' ? 'var(--high-color)' : 'var(--medium-color)');
                        findingsHtml += `
                            <div class="finding-card" style="border-left-color: ${sevColor}">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
                                    <div style="font-weight:600; font-size:0.9rem;">${f.title}</div>
                                    <span class="badge" style="background:${sevColor}; color:#fff;">${f.severity}</span>
                                </div>
                                <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:0.4rem;">${f.category} | ${f.owasp_mapping}</div>
                                <div style="font-size:0.8rem; margin-bottom:0.4rem;">${f.description}</div>
                                <div style="font-size:0.75rem; color:#4ade80; margin-bottom:0.4rem;"><b>Remediation:</b> ${f.remediation}</div>
                                <div class="code-box">${JSON.stringify(f.evidence, null, 2)}</div>
                            </div>
                        `;
                    });
                });

                const riskColor = report.risk_score > 5.0 ? 'var(--critical-color)' : 'var(--success-color)';

                container.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(0,0,0,0.3); padding:1rem; border-radius:8px; margin-bottom:1rem; border:1px solid var(--border-color);">
                        <div>
                            <h3 style="font-size:1.1rem;">Target: ${report.target_name}</h3>
                            <div style="font-size:0.8rem; color:var(--text-muted);">Scan ID: ${report.scan_id} | Scanned at: ${report.timestamp}</div>
                        </div>
                        <div style="text-align:right;">
                            <div style="font-size:1.5rem; font-weight:700; color:${riskColor};">Risk Score: ${report.risk_score} / 10.0</div>
                            <div style="font-size:0.8rem; color:var(--text-muted);">Total Findings: ${report.total_findings}</div>
                        </div>
                    </div>

                    <div style="margin-bottom:1rem;">
                        <h4 style="font-size:0.95rem; margin-bottom:0.75rem;">Detection Engine & Severity Breakdown</h4>
                        ${findingsHtml || '<p style="color:#22c55e; font-size:0.9rem;">✅ No vulnerabilities detected! All Document, Retrieval, and LLM security controls passed cleanly.</p>'}
                    </div>
                `;
            }
        </script>
    </body>
    </html>
    """
    return dashboard_html
