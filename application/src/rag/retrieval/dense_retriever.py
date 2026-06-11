"""
Dense Retriever — FAISS semantic search.

Accepts a KnowledgeBase instance to avoid redundant encoding.

Interface:
    retrieve(query, k) -> list[dict]
"""

import numpy as np
from src.rag.utils.config  import TOP_K
from src.rag.utils.helpers import format_doc


class DenseRetriever:
    def __init__(self, kb):
        """
        Args:
            kb: KnowledgeBase instance
        """
        self.kb = kb

    def retrieve(self, query: str, k: int = TOP_K) -> list[dict]:
        """
        Retrieve top-k documents by semantic similarity (FAISS L2).

        Returns:
            list of dicts: id, description, yara_rule, score, ...
        """
        query_vec          = self.kb.encode_query(query)
        distances, indices = self.kb.faiss_index.search(query_vec, k)

        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx == -1:
                continue
            score = 1 / (1 + float(dist))   # convert L2 to similarity
            results.append(format_doc(self.kb.data[idx], score))
        return results

    def get_all_scores(self, query: str) -> np.ndarray:
        """Return dense scores for ALL documents (used by HybridRetriever)."""
        n         = len(self.kb)
        query_vec = self.kb.encode_query(query)
        _, indices = self.kb.faiss_index.search(query_vec, n)

        scores = np.zeros(n)
        for rank, idx in enumerate(indices[0]):
            if idx != -1:
                scores[idx] = 1 - (rank / n)
        return scores
