"""Hallucination detector — identifies invented YARA constructs."""
import re

FAKE_CONSTRUCTS = [
    r"deleteshadowcopy\s*\(",
    r"if\s*\(\s*filetype\s*==",
    r"if\s*\(\s*algorithm\s*==",
    r"exists\s*\(\s*['\"]key",
    r"scanfile\s*\(",
    r"detect\s*\(",
    r"match\s*\(",
    r"encrypt\s*\(",
    r"filetype\s*==",
]


def compute_hallucination_score(rule_text: str) -> dict:
    rule_lower = rule_text.lower()
    found = [p for p in FAKE_CONSTRUCTS if re.search(p, rule_lower)]
    score = min(len(found) / 3, 1.0)
    return {"score": round(score, 4), "fake_constructs": found, "num_fake": len(found)}
