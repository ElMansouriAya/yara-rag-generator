"""
Agentic RAG Pipeline — full agent loop.

Flow:
    query
      → QueryAnalyzer   (analyze query → metadata)
      → RetrievalAgent  (select retriever → docs)
      → prompt_builder  (build enriched prompt)
      → LLM             (generate YARA rule)
      → ValidationAgent (validate → retry decision)
      → [retry if needed, max 2 iterations]
      → final YARA rule
"""

from src.rag.agents.query_analyzer   import QueryAnalyzer
from src.rag.agents.retrieval_agent  import RetrievalAgent
from src.rag.agents.validation_agent import ValidationAgent
from src.rag.generation.prompt_builder import build_prompt
from src.rag.generation.postprocessor  import extract_yara_rule
from src.rag.utils.config              import TOP_K


class AgenticRAG:
    def __init__(self, kb, llm, max_iterations: int = 2):
        self.llm       = llm
        self.analyzer  = QueryAnalyzer()
        self.retriever = RetrievalAgent(kb)
        self.validator = ValidationAgent()
        self.max_iter  = max_iterations

    def run(self, query: str, k: int = TOP_K) -> dict:
        """
        Run the full agentic pipeline.

        Returns:
            {
                "query"           : str,
                "pipeline"        : "agentic",
                "yara_rule"       : str,
                "sources"         : list[dict],
                "iterations"      : int,
                "valid"           : bool,
                "retriever_used"  : str,
                "analysis"        : dict,
                "validation"      : dict
            }
        """
        # ── Step 1: Analyze query ────────────────────────────────────
        analysis = self.analyzer.analyze(query)

        current_query = query
        result_rule   = ""
        retrieval_out = {}
        validation    = {}

        for iteration in range(1, self.max_iter + 1):

            # ── Step 2: Retrieve ─────────────────────────────────────
            retrieval_out = self.retriever.retrieve(current_query, analysis, k)
            docs          = retrieval_out["docs"]

            # ── Step 3: Generate ─────────────────────────────────────
            prompt      = build_prompt(current_query, docs)
            raw_output  = self.llm.generate(prompt)
            result_rule = extract_yara_rule(raw_output)

            # ── Step 4: Validate ─────────────────────────────────────
            validation = self.validator.assess(result_rule, iteration, self.max_iter)

            if not validation["should_retry"]:
                break

            # ── Step 5: Refine query for retry ────────────────────────
            suffix        = validation.get("refined_suffix") or ""
            current_query = query + suffix

        return {
            "query"          : query,
            "pipeline"       : "agentic",
            "yara_rule"      : result_rule,
            "sources"        : retrieval_out.get("docs", []),
            "iterations"     : iteration,
            "valid"          : validation.get("is_valid", False),
            "retriever_used" : retrieval_out.get("retriever_used", "hybrid"),
            "analysis"       : analysis,
            "validation"     : validation,
        }
