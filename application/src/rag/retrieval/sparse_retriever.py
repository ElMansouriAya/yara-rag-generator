"""
Sparse Retriever — BM25 keyword search.

Good for exact technical terms: AES, vssadmin, SSDT, NetShareEnum.

Interface:
    retrieve(query, k) -> list[dict]
"""

import numpy as np
from src.rag.utils.config  import TOP_K
from src.rag.utils.helpers import format_doc


class SparseRetriever:
    def __init__(self, kb):
        """
        Args:
            kb: KnowledgeBase instance
        """
        self.kb = kb

    def retrieve(self, query: str, k: int = TOP_K) -> list[dict]:
        """
        Retrieve top-k documents by BM25 keyword matching.

        Returns:
            list of dicts: id, description, yara_rule, score, ...
        """
        scores    = self.get_all_scores(query)
        top_k_idx = np.argsort(scores)[::-1][:k]

        return [format_doc(self.kb.data[i], scores[i]) for i in top_k_idx]

    def get_all_scores(self, query: str) -> np.ndarray:
        """Return BM25 scores for ALL documents (used by HybridRetriever)."""
        tokens = query.lower().split()
        scores = self.kb.bm25_index.get_scores(tokens)
        max_s  = scores.max()
        return scores / max_s if max_s > 0 else scores
