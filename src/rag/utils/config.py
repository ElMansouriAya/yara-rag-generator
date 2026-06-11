"""Global configuration — paths, model names, parameters."""
import os
from pathlib import Path

def find_project_root():
    """Find project root by looking for data/ directory."""
    current = Path(__file__).resolve()
    
    for parent in current.parents:
        if (parent / "data").exists():
            return str(parent)
        if parent == parent.parent:
            break
    
    return str(current.parent.parent.parent.parent)

BASE_DIR = find_project_root()
DATA_DIR     = os.path.join(BASE_DIR, "data")

# ── Dataset paths ──────────────────────────────────────────────────────────
# MVP dataset (dev/testing — 32 entries)
DATASET_MVP   = os.path.join(DATA_DIR, "mock_knowledge_base.json")

# Production dataset (delivered by NLP team — 3046 entries)
DATASET_PROD = os.path.join(DATA_DIR, "processed", "filtered", "dataset_production_enriched.json")

# Active dataset — switch here to change dataset
DATASET_PATH = DATASET_PROD if os.path.exists(
    os.path.join(DATA_DIR, "processed","filtered", "dataset_production_enriched.json")
) else DATASET_MVP

INDEX_DIR    = os.path.join(DATA_DIR, "indexes")
INDEX_DIR        = os.path.join(DATA_DIR, "indexes")
FAISS_INDEX_PATH = os.path.join(INDEX_DIR, "faiss_index.bin")
BM25_INDEX_PATH  = os.path.join(INDEX_DIR, "bm25_index.pkl")
EMBEDDINGS_PATH  = os.path.join(INDEX_DIR, "embeddings.npy")
META_PATH        = os.path.join(INDEX_DIR, "metadata.json")

# ── Embedding model ────────────────────────────────────────────────────────
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
# Better quality (slower): "all-mpnet-base-v2"

# ── Retrieval ──────────────────────────────────────────────────────────────
TOP_K        = 3
HYBRID_ALPHA = 0.5

# ── LLM models ────────────────────────────────────────────────────────────
LLM_MODELS = {
    "qwen"   : "Qwen/Qwen2.5-0.5B-Instruct",
    "mistral": "mistralai/Mistral-7B-Instruct-v0.3",
    "flan"   : "google/flan-t5-base",
}
DEFAULT_LLM    = "qwen"
MAX_NEW_TOKENS = 300
TEMPERATURE    = 0.3
