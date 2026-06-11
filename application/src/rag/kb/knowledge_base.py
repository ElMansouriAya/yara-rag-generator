"""
Knowledge Base — single entry point for dataset + indexes.

Loads the dataset once and builds FAISS + BM25 indexes shared
across all retrievers. Avoids redundant encoding.

Usage:
    kb = KnowledgeBase()
    dense  = DenseRetriever(kb)
    sparse = SparseRetriever(kb)
    hybrid = HybridRetriever(kb)
"""

import numpy as np
import faiss
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer

from src.rag.utils.config  import EMBEDDING_MODEL, DATASET_PATH
from src.rag.utils.helpers import load_dataset, get_embedding_texts


class KnowledgeBase:
    def __init__(self, dataset_path: str = None):
        print("[KnowledgeBase] Loading dataset...")
        self.data  = load_dataset(dataset_path)
        self.texts = get_embedding_texts(self.data)
        n = len(self.data)

        # ── Sentence embeddings ──────────────────────────────────────
        print(f"[KnowledgeBase] Encoding {n} documents...")
        self.embedder    = SentenceTransformer(EMBEDDING_MODEL)
        self.embeddings  = self.embedder.encode(
            self.texts, show_progress_bar=True, convert_to_numpy=True
        ).astype("float32")

        # ── FAISS index ──────────────────────────────────────────────
        dim              = self.embeddings.shape[1]
        self.faiss_index = faiss.IndexFlatL2(dim)
        self.faiss_index.add(self.embeddings)

        # ── BM25 index ───────────────────────────────────────────────
        tokenized        = [t.lower().split() for t in self.texts]
        self.bm25_index  = BM25Okapi(tokenized)

        print(f"[KnowledgeBase] Ready — {n} docs | dim={dim}")

    def encode_query(self, query: str) -> np.ndarray:
        """Encode a query string to a float32 vector."""
        return self.embedder.encode([query]).astype("float32")

    def __len__(self):
        return len(self.data)
