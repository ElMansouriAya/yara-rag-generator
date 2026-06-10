"""
Tests for agents.
Run: python tests/test_agents.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

VALID_RULE = """rule Test_Valid {
    meta:
        description = "Test"
    strings:
        $a = "AES" nocase
        $b = "vssadmin" nocase
    condition:
        all of them
}"""

INVALID_RULE = "rule Broken { strings: $a = \"test\" }"

HALLUCIN_RULE = "rule Bad { strings: $a = \"x\" condition: deleteshadowcopy() }"

if __name__ == "__main__":
    from src.agents.query_analyzer   import QueryAnalyzer
    from src.agents.validation_agent import ValidationAgent

    qa = QueryAnalyzer()
    va = ValidationAgent()

    print("\n=== QueryAnalyzer ===")
    tests = [
        "Ransomware encrypting files with AES",
        "Worm spreading via SMB shares",
        "Keylogger with SetWindowsHookEx and FTP",
    ]
    for q in tests:
        result = qa.analyze(q)
        print(f"  Q: {q}")
        print(f"    type={result['malware_type']} | retriever={result['suggested_retriever']} | technical={result['has_technical_terms']}")
    print("✅ QueryAnalyzer passed")

    print("\n=== ValidationAgent ===")
    r1 = va.assess(VALID_RULE,   iteration=1, max_iterations=2)
    r2 = va.assess(INVALID_RULE, iteration=1, max_iterations=2)
    r3 = va.assess(HALLUCIN_RULE,iteration=1, max_iterations=2)

    assert r1["is_valid"]    == True,  "Valid rule should pass"
    assert r2["is_valid"]    == False, "Invalid rule should fail"
    assert r2["should_retry"]== True,  "Should retry on invalid"
    print(f"  Valid rule    → valid={r1['is_valid']} retry={r1['should_retry']}")
    print(f"  Invalid rule  → valid={r2['is_valid']} retry={r2['should_retry']} reason={r2['reason']}")
    print(f"  Hallucination → score={r3['hallucination']:.2f}")
    print("✅ ValidationAgent passed")
    print("\n✅ All agent tests passed")
