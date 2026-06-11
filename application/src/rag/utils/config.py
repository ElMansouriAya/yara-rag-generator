"""Global configuration — paths, model names, parameters."""
import os

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATA_DIR     = os.path.join(BASE_DIR, "data")

# ── Dataset paths ──────────────────────────────────────────────────────────
# MVP dataset (dev/testing — 32 entries)
DATASET_MVP  = os.path.join(DATA_DIR, "processed", "dataset_yara_mvp.json")

# Production dataset (delivered by NLP team — 3046 entries)
DATASET_PROD = os.path.join(DATA_DIR, "processed", "dataset_production_enriched.json")

# Knowledge base dataset (main dataset — 33M entries)
DATASET_KB   = os.path.join(DATA_DIR, "processed", "knowledge_base.json")

# Active dataset — switch here to change dataset
# Priority: knowledge_base.json > production > mvp
DATASET_PATH = (
    DATASET_KB if os.path.exists(DATASET_KB)
    else (DATASET_PROD if os.path.exists(DATASET_PROD) else DATASET_MVP)
)

INDEX_DIR    = os.path.join(DATA_DIR, "indexes")

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
