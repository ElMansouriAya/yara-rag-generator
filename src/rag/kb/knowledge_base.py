"""
Knowledge Base — single entry point for dataset + indexes.

Loads dataset once, builds FAISS + BM25 indexes.
Saves indexes to disk on first build.
Loads from disk on subsequent runs (fast).

Index files saved in data/indexes/:
    faiss_index.bin   ← FAISS index
    bm25_index.pkl    ← BM25 index
    metadata.json     ← version info (dataset path, num docs, date)
"""

import os
import json
import pickle
import hashlib
import datetime
import numpy as np
import faiss
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer

from src.rag.utils.config  import EMBEDDING_MODEL, DATASET_PATH, INDEX_DIR
from src.rag.utils.helpers import load_dataset, get_embedding_texts


class KnowledgeBase:
    def __init__(self, dataset_path: str = None):
        self.dataset_path = dataset_path or DATASET_PATH
        os.makedirs(INDEX_DIR, exist_ok=True)

        print("[KnowledgeBase] Loading dataset...")
        self.data  = load_dataset(self.dataset_path)
        self.texts = get_embedding_texts(self.data)
        n          = len(self.data)

        self.embedder = SentenceTransformer(EMBEDDING_MODEL)

        # ── Try loading saved indexes ────────────────────────────────
        if self._indexes_valid():
            print("[KnowledgeBase] Loading saved indexes from disk...")
            self._load_indexes()
            print(f"[KnowledgeBase] Ready (from cache) — {n} docs | dim={self.embeddings.shape[1]}")
        else:
            print(f"[KnowledgeBase] Building indexes for {n} documents...")
            self._build_indexes()
            self._save_indexes()
            print(f"[KnowledgeBase] Ready (built & saved) — {n} docs | dim={self.embeddings.shape[1]}")

    # ── Index paths ──────────────────────────────────────────────────────────
    @property
    def _faiss_path(self):
        return os.path.join(INDEX_DIR, "faiss_index.bin")

    @property
    def _bm25_path(self):
        return os.path.join(INDEX_DIR, "bm25_index.pkl")

    @property
    def _meta_path(self):
        return os.path.join(INDEX_DIR, "metadata.json")

    # ── Validity check ───────────────────────────────────────────────────────
    def _dataset_hash(self) -> str:
        """Compute a hash of the dataset to detect changes."""
        sig = f"{self.dataset_path}:{len(self.data)}:{self.data[0].get('id','')}"
        return hashlib.md5(sig.encode()).hexdigest()

    def _indexes_valid(self) -> bool:
        """Return True if saved indexes exist and match current dataset."""
        if not all(os.path.exists(p) for p in
                   [self._faiss_path, self._bm25_path, self._meta_path]):
            return False
        try:
            with open(self._meta_path) as f:
                meta = json.load(f)
            return (meta.get("dataset_hash") == self._dataset_hash() and
                    meta.get("num_docs")     == len(self.data) and
                    meta.get("model")        == EMBEDDING_MODEL)
        except Exception:
            return False

    # ── Build ────────────────────────────────────────────────────────────────
    def _build_indexes(self):
        """Encode documents and build FAISS + BM25 indexes."""
        self.embeddings = self.embedder.encode(
            self.texts, show_progress_bar=True, convert_to_numpy=True
        ).astype("float32")

        # FAISS
        dim              = self.embeddings.shape[1]
        self.faiss_index = faiss.IndexFlatL2(dim)
        self.faiss_index.add(self.embeddings)

        # BM25
        tokenized        = [t.lower().split() for t in self.texts]
        self.bm25_index  = BM25Okapi(tokenized)

    # ── Save ─────────────────────────────────────────────────────────────────
    def _save_indexes(self):
        """Persist indexes to disk."""
        # FAISS
        faiss.write_index(self.faiss_index, self._faiss_path)

        # BM25
        with open(self._bm25_path, "wb") as f:
            pickle.dump(self.bm25_index, f)

        # Metadata
        meta = {
            "dataset_path" : self.dataset_path,
            "dataset_hash" : self._dataset_hash(),
            "num_docs"     : len(self.data),
            "model"        : EMBEDDING_MODEL,
            "built_at"     : datetime.datetime.now().isoformat(),
            "faiss_path"   : self._faiss_path,
            "bm25_path"    : self._bm25_path,
        }
        with open(self._meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        print(f"[KnowledgeBase] Indexes saved to {INDEX_DIR}/")

    # ── Load ─────────────────────────────────────────────────────────────────
    def _load_indexes(self):
        """Load indexes from disk."""
        # FAISS
        self.faiss_index = faiss.read_index(self._faiss_path)

        # Rebuild embeddings array for dense scorer
        # (stored separately since FAISS index doesn't expose vectors easily)
        emb_path = os.path.join(INDEX_DIR, "embeddings.npy")
        if os.path.exists(emb_path):
            self.embeddings = np.load(emb_path)
        else:
            # Fallback: re-encode (only happens once after migration)
            self.embeddings = self.embedder.encode(
                self.texts, show_progress_bar=False, convert_to_numpy=True
            ).astype("float32")
            np.save(emb_path, self.embeddings)

        # BM25
        with open(self._bm25_path, "rb") as f:
            self.bm25_index = pickle.load(f)

    # ── Public helpers ───────────────────────────────────────────────────────
    def encode_query(self, query: str) -> np.ndarray:
        """Encode a query string to a float32 vector."""
        return self.embedder.encode([query]).astype("float32")

    def rebuild(self):
        """Force rebuild indexes (use after dataset update)."""
        print("[KnowledgeBase] Forcing index rebuild...")
        self.data  = load_dataset(self.dataset_path)
        self.texts = get_embedding_texts(self.data)
        self._build_indexes()
        self._save_indexes()
        print("[KnowledgeBase] Rebuild complete.")

    def __len__(self):
        return len(self.data)
