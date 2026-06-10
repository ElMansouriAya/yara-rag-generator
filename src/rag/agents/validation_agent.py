"""
ValidationAgent — validates generated YARA rules and decides retry logic.

Combines structural validation (yara_validator) and
hallucination detection (hallucination) to produce a retry decision.
"""

from src.rag.evaluation.yara_validator import validate
from src.rag.evaluation.hallucination  import compute_hallucination_score


class ValidationAgent:
    """
    Validates a generated YARA rule and decides whether to retry.

    Decision logic:
        - If rule is structurally invalid → retry
        - If hallucination score > threshold → retry
        - If max_iterations reached → accept as-is
    """

    HALLUCINATION_THRESHOLD = 0.3

    def assess(self, yara_rule: str, iteration: int, max_iterations: int) -> dict:
        """
        Assess a generated YARA rule.

        Args:
            yara_rule      : generated rule text
            iteration      : current iteration number (1-based)
            max_iterations : maximum allowed iterations

        Returns:
            {
                "is_valid"       : bool,
                "should_retry"   : bool,
                "reason"         : str,
                "refined_query"  : str | None,
                "syntax_score"   : float,
                "hallucination"  : float,
                "validation"     : dict   (full validation report)
            }
        """
        val    = validate(yara_rule)
        halluc = compute_hallucination_score(yara_rule)

        is_valid        = val["is_valid"]
        high_hallucin   = halluc["score"] > self.HALLUCINATION_THRESHOLD
        can_retry       = iteration < max_iterations

        should_retry    = can_retry and (not is_valid or high_hallucin)

        # Build reason message
        if is_valid and not high_hallucin:
            reason = "Rule is valid and no hallucinations detected"
        elif not is_valid:
            missing = []
            if not val["has_strings"]  : missing.append("strings:")
            if not val["has_condition"]: missing.append("condition:")
            if not val["has_rule"]     : missing.append("rule keyword")
            reason = f"Invalid rule — missing: {', '.join(missing)}"
        else:
            reason = f"Hallucination detected (score={halluc['score']:.2f})"

        # Build refined query hint for retry
        refined = None
        if should_retry:
            if not val["has_strings"]:
                refined = " (add specific strings: section with $variables)"
            elif not val["has_condition"]:
                refined = " (add condition: section)"
            elif high_hallucin:
                refined = " (use only valid YARA syntax: strings, condition, filesize)"

        return {
            "is_valid"      : is_valid,
            "should_retry"  : should_retry,
            "reason"        : reason,
            "refined_suffix": refined,
            "syntax_score"  : val["syntax_score"],
            "hallucination" : halluc["score"],
            "validation"    : val,
        }
