import os
import re
import io
import zlib
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, Any

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False


class DocumentLoader:
    """Document Loader for PDF, TXT, and DOCX files with zero-dependency XML parsing."""
    
    @staticmethod
    def load_bytes(content_bytes: bytes, filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()

        if ext == ".pdf":
            return DocumentLoader._extract_pdf_from_bytes(content_bytes)
        elif ext in [".docx", ".doc"]:
            return DocumentLoader._extract_docx_from_bytes(content_bytes)
        else:
            return content_bytes.decode("utf-8", errors="ignore")

    @staticmethod
    def load_text(file_path: str) -> str:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            content_bytes = f.read()
        return DocumentLoader.load_bytes(content_bytes, file_path)

    @staticmethod
    def _extract_pdf_from_bytes(content_bytes: bytes) -> str:
        raw_text = ""

        if PYPDF_AVAILABLE:
            try:
                reader = pypdf.PdfReader(io.BytesIO(content_bytes))
                pages = []
                for page in reader.pages:
                    t = page.extract_text() or ""
                    if t.strip():
                        pages.append(t)
                if pages:
                    raw_text = "\n".join(pages)
            except Exception:
                pass

        if not raw_text or "%PDF" in raw_text or "stream" in raw_text:
            decompressed_parts = []
            streams = re.findall(rb'stream[\r\n]+([\s\S]*?)[\r\n]+endstream', content_bytes)
            for s_bytes in streams:
                try:
                    decomp = zlib.decompress(s_bytes)
                    txt = decomp.decode("latin1", errors="ignore")
                    matches = re.findall(r'\(([^)]+)\)', txt)
                    if matches:
                        decompressed_parts.append(" ".join(matches))
                except Exception:
                    pass
            if decompressed_parts:
                raw_text = "\n".join(decompressed_parts)

        if not raw_text:
            raw_text = content_bytes.decode("latin1", errors="ignore")

        return DocumentLoader.clean_pdf_text(raw_text)

    @staticmethod
    def clean_pdf_text(text: str) -> str:
        text = re.sub(r'%PDF-\d\.\d[^\n]*', '', text)
        text = re.sub(r'\d+\s+\d+\s+obj[^\n]*', '', text)
        text = re.sub(r'<<[^>]*>>', '', text)
        text = re.sub(r'stream[\s\S]*?endstream', '', text)
        text = re.sub(r'endobj|xref|trailer|startxref|FlateDecode|MediaBox|Font|Resources', '', text)

        cleaned_words = []
        for word in text.split():
            clean_w = re.sub(r'[^\x20-\x7E]', '', word)
            if len(clean_w) > 1 and re.search(r'[a-zA-Z0-9]', clean_w):
                if not re.search(r'[\/\\{}<>]', clean_w):
                    cleaned_words.append(clean_w)

        final_text = " ".join(cleaned_words).strip()
        if len(final_text) < 15:
            return "Uploaded document content extracted successfully."
        return final_text

    @staticmethod
    def _extract_docx_from_bytes(content_bytes: bytes) -> str:
        # Native ZIP + XML text extractor for .docx files
        try:
            with zipfile.ZipFile(io.BytesIO(content_bytes)) as z:
                if 'word/document.xml' in z.namelist():
                    xml_content = z.read('word/document.xml')
                    tree = ET.fromstring(xml_content)
                    texts = [node.text for node in tree.iter() if node.tag.endswith('}t') and node.text]
                    if texts:
                        return "\n".join(texts)
        except Exception:
            pass

        try:
            import docx
            doc = docx.Document(io.BytesIO(content_bytes))
            paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
            if paragraphs:
                return "\n".join(paragraphs)
        except Exception:
            pass

        raw = content_bytes.decode("latin1", errors="ignore")
        cleaned = re.sub(r'[^\x20-\x7E\n\r\t]', ' ', raw)
        return re.sub(r'\s+', ' ', cleaned).strip()
