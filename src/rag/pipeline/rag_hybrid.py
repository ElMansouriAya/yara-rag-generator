"""
Hybrid RAG Pipeline — FAISS + BM25 fusion + LLM generation.

Flow:
    query
      → DenseRetriever  (dense_scores)
      → SparseRetriever (sparse_scores)
      → fusion.fuse()   (hybrid_scores)
      → top-k docs
      → prompt_builder
      → LLM
      → YARA rule
"""

from src.rag.retrieval.hybrid_retriever import HybridRetriever
from src.rag.generation.prompt_builder  import build_prompt
from src.rag.utils.config               import TOP_K, HYBRID_ALPHA


class HybridRAG:
    def __init__(self, kb, llm, alpha: float = HYBRID_ALPHA):
        self.retriever = HybridRetriever(kb, alpha)
        self.llm       = llm

    def run(self, query: str, k: int = TOP_K) -> dict:
        docs   = self.retriever.retrieve(query, k)
        prompt = build_prompt(query, docs)
        rule   = self.llm.generate(prompt)
        return {"query": query, "pipeline": "hybrid",
                "yara_rule": rule, "sources": docs, "prompt": prompt}
