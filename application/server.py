"""
server.py — Flask API Server for YARA RAG Generator Dashboard

Provides HTTP endpoints wrapping the Python API (api.py).
Enables frontend dashboard communication with backend RAG pipeline.

Endpoints:
  GET    /health                  — Server health check
  POST   /api/generate             — Generate YARA rule from threat description
  POST   /api/explain              — Explain a YARA rule
  POST   /api/search               — Search knowledge base
  GET    /api/stats                — Get dataset statistics
  POST   /api/benchmark            — Run benchmark on all modes
  POST   /api/model                — Switch active LLM model
  POST   /api/upload-pdf           — Upload and process PDF document
  GET    /api/pdf-stats            — Get PDF upload statistics
  POST   /api/test-pdf-retrieval   — Test PDF retrieval with query

Usage:
  python server.py              # Start on port 5000 (dev)
  python run_server.py --port 8000 --model mistral
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple
from functools import wraps

# Add project root to path
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Import backend API
from api import YARARAGAPI, AVAILABLE_MODELS, AVAILABLE_MODES
from src.pdf.pdf_processor import PDFProcessor
from src.analytics.analytics import AnalyticsManager

# Load environment variables
load_dotenv()

# ── Configuration ────────────────────────────────────────────────────────────
FLASK_ENV = os.getenv("FLASK_ENV", "development")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "qwen")
DEBUG_MODE = FLASK_ENV == "development"

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO if not DEBUG_MODE else logging.DEBUG,
    format='[%(asctime)s] %(levelname)s — %(message)s'
)
logger = logging.getLogger(__name__)

# ── Flask App ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Enable CORS for frontend requests
# In production, restrict to actual frontend domain
CORS(app, resources={
    r"/api/*": {"origins": "*"},
    r"/health": {"origins": "*"}
})

# ── Global API Instance ──────────────────────────────────────────────────────
# Lazy load on first request to avoid startup delays
_api_instance = None

# ── Global PDF & Analytics ───────────────────────────────────────────────────
PDF_UPLOAD_DIR = os.path.join(ROOT, "data", "pdf_uploads")
PDF_PROCESSOR = PDFProcessor(chunk_size=500, overlap=50)
ANALYTICS = AnalyticsManager()

os.makedirs(PDF_UPLOAD_DIR, exist_ok=True)

def get_api() -> YARARAGAPI:
    """Get or initialize the API instance (lazy loading)."""
    global _api_instance
    if _api_instance is None:
        logger.info(f"Initializing YARARAGAPI with model={DEFAULT_MODEL}")
        try:
            _api_instance = YARARAGAPI(model=DEFAULT_MODEL)
        except Exception as e:
            logger.error(f"Failed to initialize API: {e}")
            raise
    return _api_instance

# ── Response Helpers ────────────────────────────────────────────────────────
def success_response(data: Any = None, status: int = 200) -> Tuple[Dict, int]:
    """Format a successful response."""
    return jsonify({"success": True, "data": data}), status

def error_response(error: str, status: int = 400) -> Tuple[Dict, int]:
    """Format an error response."""
    return jsonify({"success": False, "error": error}), status

# ── Request Validation Decorator ────────────────────────────────────────────
def require_json_fields(*fields):
    """Decorator to validate required JSON fields."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return error_response("Request must be JSON", 400)
            
            data = request.get_json()
            missing = [field for field in fields if field not in data]
            if missing:
                return error_response(
                    f"Missing required fields: {', '.join(missing)}", 400
                )
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ── Endpoints ────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint.
    
    Returns server status and available options.
    """
    try:
        api = get_api()
        return success_response({
            "status": "healthy",
            "message": "YARA RAG server is running",
            "model": api._model_name,
            "available_models": AVAILABLE_MODELS,
            "available_modes": AVAILABLE_MODES,
            "documents_loaded": len(api._kb) if hasattr(api._kb, '__len__') else 0
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return error_response(f"Server error: {str(e)}", 500)

@app.route('/api/generate', methods=['POST'])
@require_json_fields('query', 'mode')
def generate_rule():
    """
    Generate a YARA rule from a threat description.
    
    Request Body:
        {
            "query": "Ransomware encrypting files with AES...",
            "mode": "agentic" | "hybrid" | "classic" | "baseline"
        }
    
    Response:
        {
            "success": true,
            "data": {
                "query": str,
                "mode": str,
                "yara_rule": str,
                "valid": bool,
                "syntax_score": float,
                "sources": [{id, description, malware_type, ...}],
                "iterations": int,
                "retriever_used": str,
                "model": str
            }
        }
    """
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        mode = data.get('mode', '').lower()
        
        # Validation
        if not query:
            return error_response("Query cannot be empty", 400)
        if len(query) > 2000:
            return error_response("Query too long (max 2000 chars)", 400)
        if mode not in AVAILABLE_MODES:
            return error_response(
                f"Invalid mode '{mode}'. Choose from: {', '.join(AVAILABLE_MODES)}", 
                400
            )
        
        logger.info(f"Generating YARA rule — query_len={len(query)}, mode={mode}")
        api = get_api()
        result = api.generate(query, mode=mode)
        
        return success_response(result)
    
    except Exception as e:
        logger.error(f"Generation failed: {e}", exc_info=True)
        return error_response(f"Generation error: {str(e)}", 500)

@app.route('/api/explain', methods=['POST'])
@require_json_fields('yara_rule')
def explain_rule():
    """
    Generate a natural language explanation for a YARA rule.
    
    Request Body:
        {
            "yara_rule": "rule MyRule { ... }"
        }
    
    Response:
        {
            "success": true,
            "data": {
                "explanation": "This rule detects..."
            }
        }
    """
    try:
        data = request.get_json()
        yara_rule = data.get('yara_rule', '').strip()
        
        if not yara_rule:
            return error_response("YARA rule cannot be empty", 400)
        if len(yara_rule) > 5000:
            return error_response("YARA rule too long (max 5000 chars)", 400)
        
        logger.info(f"Explaining YARA rule — len={len(yara_rule)}")
        api = get_api()
        explanation = api.explain(yara_rule)
        
        return success_response({"explanation": explanation})
    
    except Exception as e:
        logger.error(f"Explanation failed: {e}", exc_info=True)
        return error_response(f"Explanation error: {str(e)}", 500)

@app.route('/api/search', methods=['POST'])
@require_json_fields('query')
def search_kb():
    """
    Search the knowledge base for relevant documents.
    
    Request Body:
        {
            "query": "Ransomware with AES encryption",
            "k": 5  (optional, default 5)
        }
    
    Response:
        {
            "success": true,
            "data": [
                {
                    "id": "...",
                    "description": "...",
                    "malware_type": "ransomware",
                    "malware_family": "...",
                    "yara_rule": "...",
                    "score": 0.85,
                    "confidence": "high",
                    "source_type": "..."
                },
                ...
            ]
        }
    """
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        k = data.get('k', 5)
        
        # Validation
        if not query:
            return error_response("Query cannot be empty", 400)
        if not isinstance(k, int) or k < 1 or k > 50:
            return error_response("k must be an integer between 1 and 50", 400)
        
        logger.info(f"Searching knowledge base — query_len={len(query)}, k={k}")
        api = get_api()
        results = api.search(query, k=k)
        
        return success_response(results)
    
    except Exception as e:
        logger.error(f"Search failed: {e}", exc_info=True)
        return error_response(f"Search error: {str(e)}", 500)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Get statistics about the loaded knowledge base.
    
    Response:
        {
            "success": true,
            "data": {
                "total": 3046,
                "synthetic": 2000,
                "original": 1046,
                "by_type": {
                    "ransomware": 500,
                    "trojan": 400,
                    ...
                },
                "by_confidence": {
                    "high": 2500,
                    "medium": 400,
                    "low": 146
                },
                "top_families": {
                    "WannaCry": 45,
                    "Emotet": 38,
                    ...
                }
            }
        }
    """
    try:
        logger.info("Fetching dataset statistics")
        api = get_api()
        stats = api.dataset_stats()
        
        return success_response(stats)
    
    except Exception as e:
        logger.error(f"Stats retrieval failed: {e}", exc_info=True)
        return error_response(f"Stats error: {str(e)}", 500)

@app.route('/api/benchmark', methods=['POST'])
@require_json_fields('queries', 'references')
def run_benchmark():
    """
    Run benchmarks across all RAG modes.
    
    Request Body:
        {
            "queries": [
                "Ransomware encrypting files with AES...",
                "Keylogger with FTP exfiltration...",
                ...
            ],
            "references": [
                "rule AES_Ransomware { ... }",
                "rule Keylogger_FTP { ... }",
                ...
            ]
        }
    
    Response:
        {
            "success": true,
            "data": {
                "summary": {
                    "agentic": {
                        "bleu": 0.65,
                        "syntax_score": 0.88,
                        "rouge_l": 0.72,
                        ...
                    },
                    "hybrid": { ... },
                    "classic": { ... },
                    "baseline": { ... }
                },
                "per_query": [
                    {
                        "query": "...",
                        "agentic": {
                            "yara_rule": "...",
                            "metrics": { ... }
                        },
                        ...
                    },
                    ...
                ],
                "model": "qwen"
            }
        }
    """
    try:
        data = request.get_json()
        queries = data.get('queries', [])
        references = data.get('references', [])
        
        # Validation
        if not isinstance(queries, list) or not isinstance(references, list):
            return error_response("queries and references must be lists", 400)
        if len(queries) != len(references):
            return error_response(
                f"Length mismatch: {len(queries)} queries vs {len(references)} references",
                400
            )
        if not queries:
            return error_response("At least one query is required", 400)
        if len(queries) > 20:
            return error_response("Maximum 20 queries per benchmark", 400)
        
        logger.info(f"Running benchmark — {len(queries)} queries on all modes")
        api = get_api()
        result = api.benchmark(queries, references)
        
        return success_response(result)
    
    except Exception as e:
        logger.error(f"Benchmark failed: {e}", exc_info=True)
        return error_response(f"Benchmark error: {str(e)}", 500)

@app.route('/api/model', methods=['POST'])
@require_json_fields('model')
def switch_model():
    """
    Switch the active LLM model without reloading the knowledge base.
    
    Request Body:
        {
            "model": "qwen" | "mistral" | "flan"
        }
    
    Response:
        {
            "success": true,
            "data": {
                "message": "Switched to qwen",
                "model": "qwen"
            }
        }
    """
    try:
        data = request.get_json()
        model = data.get('model', '').lower()
        
        if not model:
            return error_response("Model name cannot be empty", 400)
        if model not in AVAILABLE_MODELS:
            return error_response(
                f"Invalid model '{model}'. Available: {', '.join(AVAILABLE_MODELS)}",
                400
            )
        
        logger.info(f"Switching model to {model}")
        api = get_api()
        api.use_model(model)
        
        return success_response({
            "message": f"Successfully switched to {model}",
            "model": model
        })
    
    except Exception as e:
        logger.error(f"Model switch failed: {e}", exc_info=True)
        return error_response(f"Model switch error: {str(e)}", 500)

@app.route('/api/upload-pdf', methods=['POST'])
def upload_pdf():
    """
    Upload and process a PDF file.
    
    Request: multipart/form-data with 'file' field
    
    Response:
        {
            "success": true,
            "data": {
                "filename": "document.pdf",
                "pages": 10,
                "documents": 45,
                "file_size": 524288,
                "upload_time": "2024-01-15T10:30:00"
            }
        }
    """
    try:
        if 'file' not in request.files:
            return error_response("No file provided", 400)
        
        file = request.files['file']
        
        if not file.filename:
            return error_response("No file selected", 400)
        
        if not file.filename.lower().endswith('.pdf'):
            return error_response("Only PDF files are supported", 400)
        
        # Save uploaded file
        filename = os.path.basename(file.filename)
        filepath = os.path.join(PDF_UPLOAD_DIR, filename)
        file.save(filepath)
        
        logger.info(f"Processing PDF upload: {filename}")
        
        # Process PDF
        chunks, metadata = PDF_PROCESSOR.process_pdf(filepath)
        
        # Track in analytics
        ANALYTICS.track_pdf_upload(
            filename=filename,
            num_docs=len(chunks),
            file_size=metadata["file_size"],
            pages=metadata["pages"]
        )
        
        return success_response({
            "filename": filename,
            "pages": metadata["pages"],
            "documents": len(chunks),
            "file_size": metadata["file_size"],
            "upload_time": metadata["extracted_at"]
        }, 201)
    
    except Exception as e:
        logger.error(f"PDF upload failed: {e}", exc_info=True)
        return error_response(f"PDF upload error: {str(e)}", 500)

@app.route('/api/pdf-stats', methods=['GET'])
def get_pdf_stats():
    """
    Get PDF upload statistics.
    
    Response:
        {
            "success": true,
            "data": {
                "total_pdfs": 5,
                "total_documents": 250,
                "total_size_mb": 12.5,
                "uploads": [...]
            }
        }
    """
    try:
        logger.info("Fetching PDF statistics")
        stats = ANALYTICS.get_pdf_stats()
        return success_response(stats)
    
    except Exception as e:
        logger.error(f"PDF stats retrieval failed: {e}", exc_info=True)
        return error_response(f"PDF stats error: {str(e)}", 500)

@app.route('/api/test-pdf-retrieval', methods=['POST'])
def test_pdf_retrieval():
    """
    Test PDF retrieval by searching uploaded PDFs.
    
    Request:
        {
            "query": "search term",
            "filename": "optional.pdf"
        }
    
    Response:
        {
            "success": true,
            "data": {
                "query": "search term",
                "results": [
                    {
                        "content": "chunk text",
                        "score": 0.91,
                        "source": "document.pdf",
                        "chunk_id": "abc123"
                    }
                ]
            }
        }
    """
    try:
        data = request.get_json() or {}
        query = data.get('query', '').strip()
        filename = data.get('filename')
        
        if not query:
            return error_response("Query is required", 400)
        
        logger.info(f"Testing PDF retrieval: {query}")
        
        # Get the API instance
        api = get_api()
        
        # Search using API's search method
        search_result = api.search(query, k=5)
        
        # Filter by filename if specified
        results = []
        for item in search_result.get('results', []):
            if filename is None or item.get('source', '').endswith(filename):
                results.append({
                    'content': item.get('content', ''),
                    'score': item.get('similarity', 0),
                    'source': item.get('source', 'unknown'),
                    'chunk_id': item.get('chunk_id', '')
                })
        
        ANALYTICS.track_retrieval(from_pdf=True)
        
        return success_response({
            'query': query,
            'results': results[:5]
        })
    
    except Exception as e:
        logger.error(f"PDF retrieval test failed: {e}", exc_info=True)
        return error_response(f"PDF retrieval test error: {str(e)}", 500)

# ── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return error_response("Endpoint not found", 404)

@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    return error_response("Method not allowed", 405)

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return error_response("Internal server error", 500)

# ── Startup/Shutdown ─────────────────────────────────────────────────────────

@app.before_request
def log_request():
    """Log incoming requests."""
    logger.debug(f"{request.method} {request.path}")

@app.after_request
def log_response(response):
    """Log response status."""
    logger.debug(f"Response: {response.status_code}")
    return response

# ── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logger.info(f"Starting YARA RAG Server")
    logger.info(f"Environment: {FLASK_ENV}")
    logger.info(f"Port: {FLASK_PORT}")
    logger.info(f"Default Model: {DEFAULT_MODEL}")
    logger.info(f"Debug: {DEBUG_MODE}")
    
    app.run(
        host='0.0.0.0',
        port=FLASK_PORT,
        debug=DEBUG_MODE,
        threaded=True
    )
