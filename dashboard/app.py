from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from rag_app.ingestion.loader import DocumentLoader
from rag_sec.core.models import TargetConfig, TargetType
from rag_sec.core.connector import LocalPythonRAGConnector
from scanner.engine import ScannerEngine
from rag_app.api.main import vector_store, retriever, chunker, LLMGenerator, Chunk

app = FastAPI(title="RAGShield Dashboard", version="1.0.0")

scan_history: List[Dict[str, Any]] = []

class QueryReq(BaseModel):
    prompt: str
    user_context: Optional[Dict[str, Any]] = {"role": "USER", "tenant_id": "tenant_a"}
    security_enabled: bool = False

@app.post("/api/documents/upload")
async def upload_docs(
    files: List[UploadFile] = File(...),
    tenant_id: str = Form("tenant_a"),
    role_required: str = Form("USER")
):
    vector_store.chunks.clear()  # Clear old cached binary chunks before indexing new document
    summary = []
    for file in files:
        b = await file.read()
        text = DocumentLoader.load_bytes(b, file.filename)
        chunks = chunker.split_text(text, source_name=file.filename)
        for c in chunks:
            c.metadata["tenant_id"] = tenant_id
            c.metadata["role_required"] = role_required
            vector_store.add_chunk(c)
        summary.append({"filename": file.filename, "chunks": len(chunks)})

    return {"status": "SUCCESS", "uploaded": summary, "total_chunks": len(vector_store.chunks)}

@app.post("/api/documents/clear")
def clear_vector_store():
    vector_store.chunks.clear()
    return {"status": "SUCCESS", "message": "Vector store memory cleared."}

@app.post("/api/rag/query")
def query_rag(req: QueryReq):
    chunks = retriever.retrieve(req.prompt, top_k=3, user_context=req.user_context, security_enabled=req.security_enabled)
    generator = LLMGenerator(security_enabled=req.security_enabled)
    answer = generator.generate_response(req.prompt, chunks, user_context=req.user_context)
    return {
        "answer": answer,
        "retrieved_docs": [{"chunk_id": c.chunk_id, "content": c.content, "metadata": c.metadata} for c in chunks]
    }

@app.post("/api/scan")
def run_scan(guarded: bool = False):
    def rag_query(prompt, context):
        chunks = retriever.retrieve(prompt, top_k=3, user_context=context, security_enabled=guarded)
        gen = LLMGenerator(security_enabled=guarded)
        ans = gen.generate_response(prompt, chunks, user_context=context)
        return {"answer": ans, "retrieved_docs": [{"content": c.content, "metadata": c.metadata} for c in chunks]}

    def rag_ingest(content, metadata):
        metadata = metadata or {}
        if guarded:
            content = content.replace("\u200b", "").replace("\u200c", "")
            content = content.replace("SYSTEM OVERRIDE", "[FILTERED]").replace("SYSTEM MESSAGE:", "[FILTERED]")
            if metadata.get("role_required") == "PUBLIC" and metadata.get("admin_override"):
                metadata["role_required"] = "RESTRICTED"

        c = Chunk(chunk_id=f"scan-chunk-{len(vector_store.chunks)}", content=content, metadata=metadata)
        vector_store.add_chunk(c)
        return True

    config = TargetConfig(name=f"RAGShield Application ({'Secured' if guarded else 'Vulnerable'})", target_type=TargetType.LOCAL_PYTHON)
    connector = LocalPythonRAGConnector(config=config, query_fn=rag_query, ingest_fn=rag_ingest)
    
    engine = ScannerEngine(connector)
    report = engine.execute_audit()
    scan_history.insert(0, report)
    return report

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>RAGShield // Security Audit Platform</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root { --bg:#0b0f19; --card:rgba(22,30,46,0.8); --accent:#00f2fe; --text:#f1f5f9; --muted:#94a3b8; --border:rgba(255,255,255,0.1); }
            * { box-sizing:border-box; margin:0; padding:0; }
            body { font-family:'Inter', sans-serif; background:var(--bg); color:var(--text); padding:1.5rem; }
            .nav { display:flex; justify-content:space-between; align-items:center; margin-bottom:1.5rem; border-bottom:1px solid var(--border); padding-bottom:1rem; }
            .logo { font-size:1.4rem; font-weight:700; color:var(--accent); }
            .grid { display:grid; grid-template-columns: 1fr 1fr 1fr; gap:1.25rem; }
            .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:1.25rem; }
            .btn { width:100%; padding:0.7rem; border:none; border-radius:6px; background:linear-gradient(135deg, #00f2fe, #4facfe); color:#000; font-weight:600; cursor:pointer; margin-top:0.5rem; }
            .btn-danger { background:linear-gradient(135deg, #ef4444, #dc2626); color:#fff; }
            input, select, textarea { width:100%; padding:0.6rem; background:#05070a; border:1px solid var(--border); color:#fff; border-radius:6px; margin-top:0.3rem; margin-bottom:0.8rem; }
            .finding { background:rgba(15,23,42,0.8); border-left:4px solid #ef4444; border-radius:6px; padding:0.75rem; margin-bottom:0.75rem; font-size:0.85rem; }
        </style>
    </head>
    <body>
        <div class="nav">
            <div class="logo">🛡️ RAGShield // Security Audit Platform</div>
            <div style="font-size:0.85rem; color:var(--muted)">Modular RAG Pipeline & Automated Vulnerability Scanner</div>
        </div>

        <div class="grid">
            <div class="card">
                <h3>📁 Ingestion Phase</h3>
                <form id="upForm">
                    <label>Documents (PDF/TXT)</label>
                    <input type="file" id="fIn" multiple required>
                    <label>Tenant ID</label>
                    <input type="text" id="tId" value="tenant_a">
                    <button type="submit" class="btn" id="upBtn">Upload & Embed into Vector Store</button>
                </form>
                <div id="upStatus" style="margin-top:0.5rem; font-size:0.8rem;"></div>
            </div>

            <div class="card">
                <h3>🔍 Retrieval & Generation</h3>
                <form id="qForm">
                    <label>User Query</label>
                    <textarea id="pIn" rows="2" placeholder="Query document database..."></textarea>
                    <label>Security Guardrails</label>
                    <select id="secG"><option value="false">Off (Vulnerable)</option><option value="true">On (Secured)</option></select>
                    <button type="submit" class="btn">Query RAG Pipeline</button>
                </form>
                <div id="qAns" style="margin-top:0.5rem; font-size:0.8rem;"></div>
            </div>

            <div class="card">
                <h3>🛡️ Security Scanner</h3>
                <form id="scForm">
                    <label>Audit Security Mode</label>
                    <select id="scMode"><option value="false">Audit Vulnerable Baseline</option><option value="true">Audit Guarded Baseline</option></select>
                    <button type="submit" class="btn btn-danger" id="scBtn">🚀 Run RAGShield Security Audit</button>
                </form>
            </div>
        </div>

        <div class="card" style="margin-top:1.5rem;">
            <h3>📊 Risk Assessment & Security Report</h3>
            <div id="scReport" style="margin-top:1rem; font-size:0.85rem;">Click "Run RAGShield Security Audit" to audit RAG security controls.</div>
        </div>

        <script>
            document.getElementById('upForm').onsubmit = async (e) => {
                e.preventDefault();
                const fd = new FormData();
                const files = document.getElementById('fIn').files;
                for(let i=0; i<files.length; i++) fd.append('files', files[i]);
                fd.append('tenant_id', document.getElementById('tId').value);
                const res = await fetch('/api/documents/upload', {method:'POST', body:fd});
                const d = await res.json();
                document.getElementById('upStatus').innerHTML = '<span style="color:#22c55e">✅ Indexed '+d.total_chunks+' chunks!</span>';
            };

            document.getElementById('qForm').onsubmit = async (e) => {
                e.preventDefault();
                const res = await fetch('/api/rag/query', {
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({
                        prompt: document.getElementById('pIn').value,
                        security_enabled: document.getElementById('secG').value === 'true'
                    })
                });
                const d = await res.json();
                document.getElementById('qAns').innerText = 'Answer: ' + d.answer;
            };

            document.getElementById('scForm').onsubmit = async (e) => {
                e.preventDefault();
                const g = document.getElementById('scMode').value === 'true';
                const res = await fetch('/api/scan?guarded=' + g, {method:'POST'});
                const r = await res.json();
                
                let findingsHtml = '';
                r.findings.forEach(f => {
                    findingsHtml += '<div class="finding"><b>['+f.severity+'] '+f.title+'</b><br>'+f.description+'<br><span style="color:#4ade80">Remediation: '+f.remediation+'</span></div>';
                });

                document.getElementById('scReport').innerHTML = `
                    <div style="font-size:1.2rem; font-weight:700; color:${r.risk_score > 5 ? '#ef4444' : '#4ade80'}">Overall Risk Score: ${r.risk_score} / 10.0</div>
                    <div style="color:var(--muted); margin-bottom:1rem;">Total Findings: ${r.total_findings} | Report File: ${r.report_file}</div>
                    ${findingsHtml || '<p style="color:#4ade80">✅ Zero security vulnerabilities detected!</p>'}
                `;
            };
        </script>
    </body>
    </html>
    """
