"""
Post-processor — extracts and cleans YARA rule blocks from raw LLM output.
"""

import re


def extract_yara_rule(raw_output: str) -> str:
    """
    Extract the YARA rule block from raw LLM output.

    Handles:
        - ```yara ... ``` markdown blocks
        - ``` ... ``` generic code blocks
        - Raw rule ... { } blocks
    """
    patterns = [
        r"```yara\s*(rule\s+\w+.*?})\s*```",
        r"```\s*(rule\s+\w+.*?})\s*```",
        r"(rule\s+\w+\s*\{.*?})",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw_output, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()

    # Fallback: strip markdown and return
    cleaned = raw_output.strip()
    cleaned = re.sub(r"```(?:yara)?", "", cleaned).strip()
    return cleaned
