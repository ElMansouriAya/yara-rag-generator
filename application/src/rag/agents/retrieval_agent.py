"""
RetrievalAgent — decides which retriever to use and executes retrieval.

Uses QueryAnalyzer output to make an informed decision.
Falls back to HybridRetriever by default.
"""

from src.rag.retrieval.dense_retriever  import DenseRetriever
from src.rag.retrieval.sparse_retriever import SparseRetriever
from src.rag.retrieval.hybrid_retriever import HybridRetriever
from src.rag.utils.config               import TOP_K


class RetrievalAgent:
    """
    Selects the appropriate retriever based on query analysis,
    then executes retrieval and returns documents.
    """

    def __init__(self, kb):
        """
        Args:
            kb: KnowledgeBase instance
        """
        self.dense  = DenseRetriever(kb)
        self.sparse = SparseRetriever(kb)
        self.hybrid = HybridRetriever(kb)

    def retrieve(self, query: str, analysis: dict, k: int = TOP_K) -> dict:
        """
        Select retriever and execute retrieval.

        Args:
            query    : original user query
            analysis : output from QueryAnalyzer.analyze()
            k        : number of documents to return

        Returns:
            {
                "docs"             : list[dict],
                "retriever_used"   : str,
                "decision_reason"  : str
            }
        """
        suggested = analysis.get("suggested_retriever", "hybrid")

        if suggested == "sparse":
            docs   = self.sparse.retrieve(query, k)
            used   = "sparse"
            reason = "Query contains multiple exact technical keywords — BM25 preferred"

        elif suggested == "dense":
            docs   = self.dense.retrieve(query, k)
            used   = "dense"
            reason = "Long semantic query — FAISS embedding preferred"

        else:
            docs   = self.hybrid.retrieve(query, k)
            used   = "hybrid"
            reason = "Default hybrid fusion (FAISS + BM25)"

        return {
            "docs"            : docs,
            "retriever_used"  : used,
            "decision_reason" : reason,
        }
