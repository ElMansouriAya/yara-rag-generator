"""
Pipeline Orchestrator — single entry point for Dashboard and benchmarking.

Exposes:
    pipeline.run(query, mode)          → single rule generation
    pipeline.explain(yara_rule)        → natural language explanation
    pipeline.benchmark(queries, refs)  → full model comparison
    pipeline.set_llm(llm)             → swap LLM at runtime
"""

from src.rag.kb.knowledge_base         import KnowledgeBase
from src.rag.pipeline.rag_classic      import ClassicRAG
from src.rag.pipeline.rag_hybrid       import HybridRAG
from src.rag.pipeline.rag_agentic      import AgenticRAG
from src.rag.generation.prompt_builder import build_explanation_prompt
from src.rag.evaluation.metrics        import evaluate_result, average_metrics
from src.rag.utils.config              import TOP_K

MODES = ["baseline", "classic", "hybrid", "agentic"]


class YARAPipeline:
    """
    Central orchestrator. Used by Dashboard team and benchmark script.

        from src.rag.pipeline.pipeline import YARAPipeline
        pipeline = YARAPipeline(llm=QwenLLM())

        # Or pass existing kb to avoid reloading:
        pipeline = YARAPipeline(llm=QwenLLM(), kb=existing_kb)
    """

    def __init__(self, llm, dataset_path: str = None, kb=None):
        self.llm = llm
        # Accept external KB (used by benchmark to share across models)
        self.kb  = kb if kb is not None else KnowledgeBase(dataset_path)
        self._build_pipelines()
        print(f"[YARAPipeline] Ready | LLM={llm.name} | modes={MODES}")

    def _build_pipelines(self):
        self.classic = ClassicRAG(self.kb, self.llm)
        self.hybrid  = HybridRAG(self.kb,  self.llm)
        self.agentic = AgenticRAG(self.kb, self.llm)

    def set_llm(self, llm):
        """Swap the LLM without reloading the knowledge base."""
        self.llm = llm
        self._build_pipelines()
        print(f"[YARAPipeline] LLM switched to {llm.name}")

    def run(self, query: str, mode: str = "agentic", k: int = TOP_K) -> dict:
        """
        Run a single query through the chosen pipeline.

        Args:
            query : threat description
            mode  : baseline | classic | hybrid | agentic

        Returns:
            dict with yara_rule, sources, valid, iterations, ...
        """
        assert mode in MODES, f"Unknown mode. Choose from {MODES}"
        if   mode == "baseline": return self.classic.run_baseline(query)
        elif mode == "classic" : return self.classic.run(query, k)
        elif mode == "hybrid"  : return self.hybrid.run(query, k)
        elif mode == "agentic" : return self.agentic.run(query, k)

    def explain(self, yara_rule: str) -> str:
        """
        Generate a natural language explanation of a YARA rule.

        Args:
            yara_rule: generated or retrieved YARA rule string

        Returns:
            str: plain English explanation
        """
        prompt = build_explanation_prompt(yara_rule)
        return self.llm.generate(prompt)

    def benchmark(self, queries: list[str], references: list[str],
                  k: int = TOP_K) -> dict:
        """
        Benchmark all 4 modes on a list of queries.

        Returns:
            {
                "per_query": list[dict],
                "summary"  : { mode: { metric: float } }
            }
        """
        assert len(queries) == len(references)
        all_results  = []
        summary_data = {m: [] for m in MODES}

        for query, reference in zip(queries, references):
            row = {"query": query}
            for mode in MODES:
                result  = self.run(query, mode=mode, k=k)
                metrics = evaluate_result(
                    query     = query,
                    generated = result["yara_rule"],
                    reference = reference,
                    retrieved = result.get("sources", [])
                )
                row[mode] = {
                    "yara_rule": result["yara_rule"],
                    "metrics"  : metrics,
                    "sources"  : [s["id"] for s in result.get("sources", [])],
                }
                summary_data[mode].append(metrics)
            all_results.append(row)

        return {
            "per_query": all_results,
            "summary"  : {m: average_metrics(summary_data[m]) for m in MODES}
        }
