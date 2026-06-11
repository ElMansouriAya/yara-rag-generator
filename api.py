"""
api.py — Public API for the Dashboard Team.

This is the ONLY file the Dashboard team needs to import.
All RAG internals are hidden behind this interface.

Usage:
    from api import YARARAGAPI
    api = YARARAGAPI()
    
    # Generate a rule
    result = api.generate(query, mode="agentic")
    
    # Explain a rule
    explanation = api.explain(result["yara_rule"])
    
    # Benchmark all modes
    report = api.benchmark(queries, references)
    
    # Get dataset stats
    stats = api.dataset_stats()
    
    # Switch LLM
    api.use_model("mistral")
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.rag.kb.knowledge_base      import KnowledgeBase
from src.rag.pipeline.pipeline      import YARAPipeline
from src.rag.utils.helpers          import get_dataset_stats
from src.rag.evaluation.yara_validator import validate


# ── Available LLMs ───────────────────────────────────────────────────────────
AVAILABLE_MODELS = ["qwen", "flan", "mistral"]
DEFAULT_MODEL    = "qwen"
AVAILABLE_MODES  = ["agentic", "hybrid", "classic", "baseline"]


def _load_llm(model_name: str):
    """Load an LLM by name."""
    import importlib
    mapping = {
        "qwen"   : ("src.rag.generation.llm_qwen",    "QwenLLM"),
        "mistral": ("src.rag.generation.llm_mistral",  "MistralLLM"),
        "flan"   : ("src.rag.generation.llm_flan",     "FlanLLM"),
    }
    assert model_name in mapping, f"Unknown model. Choose from {AVAILABLE_MODELS}"
    module_path, class_name = mapping[model_name]
    module = importlib.import_module(module_path)
    return getattr(module, class_name)()


class YARARAGAPI:
    """
    Public API — single entry point for the Dashboard team.
    
    Parameters
    ----------
    model : str
        LLM to use: "qwen" | "flan" | "mistral" (default: "qwen")
    dataset_path : str, optional
        Custom dataset path. Uses production dataset by default.
    """

    def __init__(self, model: str = DEFAULT_MODEL, dataset_path: str = None):
        print(f"[API] Initializing YARA RAG API — model={model}")
        self._model_name = model
        self._llm        = _load_llm(model)
        self._kb         = KnowledgeBase(dataset_path)
        self._pipeline   = YARAPipeline(llm=self._llm, kb=self._kb)
        self._default_mode = "agentic"
        print(f"[API] Ready — {len(self._kb)} documents loaded")

    # ── Core methods ─────────────────────────────────────────────────────────

    def generate(self, query: str, mode: str = None) -> dict:
        """
        Generate a YARA rule from a natural language threat description.

        Parameters
        ----------
        query : str
            Natural language description of the malware behavior.
            Example: "Ransomware encrypting files with AES and deleting shadow copies"

        mode : str
            RAG architecture to use:
            - "agentic"  : full agent loop with validation (recommended)
            - "hybrid"   : FAISS + BM25 fusion
            - "classic"  : dense retrieval only
            - "baseline" : no retrieval (LLM only)

        Returns
        -------
        dict:
            {
                "query"          : str,
                "mode"           : str,
                "yara_rule"      : str,    ← the generated YARA rule
                "valid"          : bool,   ← structural validity
                "syntax_score"   : float,  ← 0.0 to 1.0
                "sources"        : list,   ← retrieved documents used
                "iterations"     : int,    ← agentic only
                "retriever_used" : str,    ← agentic only
                "model"          : str,
            }
        """
        assert mode in AVAILABLE_MODES, \
            f"Unknown mode '{mode}'. Choose from {AVAILABLE_MODES}"

        result = self._pipeline.run(query, mode=mode)

        # Add validation info
        yara_val = validate(result["yara_rule"])

        return {
            "query"         : query,
            "mode"          : mode,
            "yara_rule"     : result["yara_rule"],
            "valid"         : yara_val["is_valid"],
            "syntax_score"  : yara_val["syntax_score"],
            "sources"       : self._format_sources(result.get("sources", [])),
            "iterations"    : result.get("iterations", 1),
            "retriever_used": result.get("retriever_used", ""),
            "model"         : self._model_name,
        }

    def explain(self, yara_rule: str) -> str:
        """
        Generate a natural language explanation of a YARA rule.

        Parameters
        ----------
        yara_rule : str
            The YARA rule to explain (generated or from the knowledge base).

        Returns
        -------
        str: plain English explanation covering:
            - what behavior it detects
            - key strings used
            - condition logic
            - false positive risks
        """
        return self._pipeline.explain(yara_rule)

    def benchmark(self,
                  queries    : list[str],
                  references : list[str]) -> dict:
        """
        Benchmark all RAG modes on a set of queries.

        Parameters
        ----------
        queries    : list of threat descriptions
        references : list of reference YARA rules (ground truth)

        Returns
        -------
        dict:
            {
                "summary"   : {        ← averaged metrics per mode
                    "agentic" : { "bleu": 0.x, "syntax_score": 0.x, ... },
                    "hybrid"  : { ... },
                    "classic" : { ... },
                    "baseline": { ... },
                },
                "per_query" : [        ← detailed results per query
                    {
                        "query"    : str,
                        "agentic"  : { "yara_rule": str, "metrics": dict },
                        "hybrid"   : { ... },
                        ...
                    }
                ],
                "model" : str,
            }
        """
        result = self._pipeline.benchmark(queries, references)
        result["model"] = self._model_name
        return result

    def search(self, query: str, k: int = 5) -> list[dict]:
        """
        Search the knowledge base without generating a rule.
        Useful for displaying similar examples in the dashboard.

        Parameters
        ----------
        query : str  — threat description
        k     : int  — number of results (default 5)

        Returns
        -------
        list of dicts:
            [
                {
                    "id"           : str,
                    "description"  : str,
                    "malware_type" : str,
                    "malware_family": str,
                    "yara_rule"    : str,
                    "score"        : float,
                    "confidence"   : str,
                    "source_type"  : str,
                }
            ]
        """
        from src.rag.retrieval.hybrid_retriever import HybridRetriever
        retriever = HybridRetriever(self._kb)
        return retriever.retrieve(query, k=k)

    def dataset_stats(self) -> dict:
        """
        Return statistics about the loaded knowledge base.

        Returns
        -------
        dict:
            {
                "total"       : int,
                "synthetic"   : int,
                "original"    : int,
                "by_type"     : { malware_type: count },
                "by_confidence": { level: count },
                "top_families": { family: count },
            }
        """
        return get_dataset_stats(self._kb.data)

    def use_model(self, model_name: str) -> None:
        """
        Switch the LLM without reloading the knowledge base.

        Parameters
        ----------
        model_name : "qwen" | "flan" | "mistral"
        """
        assert model_name in AVAILABLE_MODELS, \
            f"Unknown model. Choose from {AVAILABLE_MODELS}"
        self._llm        = _load_llm(model_name)
        self._model_name = model_name
        self._pipeline.set_llm(self._llm)
        print(f"[API] Switched to model: {model_name}")


    def use_mode(self, mode: str) -> None:
        """
        Set the default RAG mode for all subsequent generate() calls.

        Parameters
        ----------
        mode : "agentic" | "hybrid" | "classic" | "baseline"
        """
        assert mode in AVAILABLE_MODES, \
            f"Unknown mode '{mode}'. Choose from {AVAILABLE_MODES}"
        self._default_mode = mode
        print(f"[API] Default mode set to: {mode}")

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _format_sources(self, sources: list[dict]) -> list[dict]:
        """Return clean source info for dashboard display."""
        return [
            {
                "id"            : s.get("id", ""),
                "description"   : s.get("description", "")[:120] + "...",
                "malware_type"  : s.get("malware_type", ""),
                "malware_family": s.get("malware_family", ""),
                "score"         : s.get("score", 0.0),
                "confidence"    : s.get("confidence", ""),
                "source_type"   : s.get("source_type", ""),
            }
            for s in sources
        ]
