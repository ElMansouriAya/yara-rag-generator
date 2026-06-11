"""
Prompt Builder — constructs enriched prompts for YARA rule generation.

Three prompt types:
    1. build_prompt()          — enriched RAG prompt (with retrieved context)
    2. build_baseline_prompt() — no context (baseline)
    3. build_explanation_prompt() — explain a generated rule
"""


def build_prompt(query: str, retrieved_docs: list[dict]) -> str:
    """Build an enriched prompt using retrieved documents as context."""

    context_blocks = []
    for i, doc in enumerate(retrieved_docs, 1):
        ioc_str      = ", ".join(doc.get("ioc", []))
        behavior_str = ", ".join(doc.get("behavior_summary", []))                        if isinstance(doc.get("behavior_summary"), list)                        else str(doc.get("behavior_summary", ""))
        block = f"""--- Example {i} ---
Malware Type : {doc.get("malware_type", "unknown")}
Family       : {doc.get("malware_family", "unknown")}
Attack Stage : {doc.get("attack_stage", "unknown")}
Behaviors    : {behavior_str}
IOC          : {ioc_str}
YARA Rule    :
{doc.get("yara_rule", "")}"""
        context_blocks.append(block)

    context = "\n\n".join(context_blocks)

    return f"""You are a cybersecurity expert specialized in writing YARA rules for malware detection.

Use the following examples as reference:

{context}

---
Generate a YARA rule for this threat:
Description: {query}

Requirements:
- meta: section with description field
- strings: section with relevant $variables
- condition: section with logical expression
- Use nocase where appropriate
- Add filesize constraint if relevant

Return ONLY the YARA rule, no explanation.

YARA Rule:"""


def build_baseline_prompt(query: str) -> str:
    """Prompt without any retrieved context — used for baseline comparison."""
    return f"""You are a cybersecurity expert specialized in writing YARA rules.

Generate a YARA rule for:
{query}

Requirements:
- meta: section with description
- strings: section with $variables
- condition: section

Return ONLY the YARA rule.

YARA Rule:"""


def build_explanation_prompt(yara_rule: str) -> str:
    """Build a prompt to generate a natural language explanation of a YARA rule."""
    return f"""You are a cybersecurity expert. Explain this YARA rule in plain English.

YARA Rule:
{yara_rule}

Explain:
1. What malware behavior it detects
2. Key strings and patterns used
3. The condition logic
4. Potential false positive risks

Explanation:"""
