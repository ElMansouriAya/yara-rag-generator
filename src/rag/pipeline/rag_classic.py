"""
Classic RAG Pipeline — Dense retrieval + LLM generation.
Used as baseline for comparison against Hybrid and Agentic.

Flow: query → DenseRetriever → prompt → LLM → YARA rule
"""

from src.rag.retrieval.dense_retriever import DenseRetriever
from src.rag.generation.prompt_builder import build_prompt, build_baseline_prompt
from src.rag.utils.config              import TOP_K


class ClassicRAG:
    def __init__(self, kb, llm):
        self.retriever = DenseRetriever(kb)
        self.llm       = llm

    def run(self, query: str, k: int = TOP_K) -> dict:
        docs   = self.retriever.retrieve(query, k)
        prompt = build_prompt(query, docs)
        rule   = self.llm.generate(prompt)
        return {"query": query, "pipeline": "classic",
                "yara_rule": rule, "sources": docs, "prompt": prompt}

    def run_baseline(self, query: str) -> dict:
        prompt = build_baseline_prompt(query)
        rule   = self.llm.generate(prompt)
        return {"query": query, "pipeline": "baseline",
                "yara_rule": rule, "sources": [], "prompt": prompt}
