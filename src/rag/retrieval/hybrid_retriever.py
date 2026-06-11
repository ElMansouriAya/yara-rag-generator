"""
Hybrid Retriever — FAISS + BM25 fusion.

Uses fusion.py for explicit, documented score combination.

Interface:
    retrieve(query, k, alpha) -> list[dict]
"""

import numpy as np
from src.rag.retrieval.dense_retriever  import DenseRetriever
from src.rag.retrieval.sparse_retriever import SparseRetriever
from src.rag.retrieval.fusion           import fuse
from src.rag.utils.config               import TOP_K, HYBRID_ALPHA
from src.rag.utils.helpers              import format_doc


class HybridRetriever:
    def __init__(self, kb, alpha: float = HYBRID_ALPHA):
        """
        Args:
            kb   : KnowledgeBase instance
            alpha: weight for dense scores (default 0.5)
        """
        self.kb     = kb
        self.alpha  = alpha
        self.dense  = DenseRetriever(kb)
        self.sparse = SparseRetriever(kb)

    def retrieve(self, query: str, k: int = TOP_K) -> list[dict]:
        """
        Retrieve top-k documents using hybrid dense + sparse fusion.

        Flow:
            1. Compute dense scores  (DenseRetriever)
            2. Compute sparse scores (SparseRetriever)
            3. Fuse via fusion.fuse()
            4. Return top-k

        Returns:
            list of dicts sorted by hybrid score
        """
        dense_scores  = self.dense.get_all_scores(query)
        sparse_scores = self.sparse.get_all_scores(query)
        hybrid_scores = fuse(dense_scores, sparse_scores, self.alpha)

        top_k_idx = np.argsort(hybrid_scores)[::-1][:k]
        return [format_doc(self.kb.data[i], hybrid_scores[i]) for i in top_k_idx]
