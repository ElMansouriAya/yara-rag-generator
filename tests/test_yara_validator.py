"""Tests for YARA validator."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

if __name__ == "__main__":
    from src.rag.evaluation.yara_validator import validate

    valid = """rule Test { meta: description = "x" strings: $a = "AES" nocase condition: $a }"""
    bad   = "rule Broken { strings: $a = \"test\" }"

    r1 = validate(valid)
    r2 = validate(bad)

    assert r1["is_valid"]  == True
    assert r2["is_valid"]  == False
    assert r1["syntax_score"] > r2["syntax_score"]
    print(f"Valid   → score={r1['syntax_score']} valid={r1['is_valid']}")
    print(f"Invalid → score={r2['syntax_score']} valid={r2['is_valid']}")
    print("✅ YARA validator tests passed")
