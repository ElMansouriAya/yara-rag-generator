"""
Tests for retrievers.
Run: python tests/test_retrieval.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

QUERIES = [
    "Ransomware encrypting files with AES and deleting shadow copies",
    "Keylogger intercepting keystrokes via FTP",
    "Worm spreading through SMB shares",
    "Backdoor using DNS tunneling for C2",
    "Cryptominer using XMRig to mine Monero",
]

def test_retriever(name, fn, k=3):
    print(f"\n=== {name} ===")
    for q in QUERIES:
        results = fn(q, k)
        assert len(results) == k
        for doc in results:
            assert "id" in doc and "yara_rule" in doc and "score" in doc
            assert 0 <= doc["score"] <= 1
        ids = [f"{r['id']}({r['score']:.2f})" for r in results]
        print(f"  {q[:50]}...")
        print(f"    → {" | ".join(ids)}")
    print(f"✅ {name} passed")

if __name__ == "__main__":
    from src.kb.knowledge_base          import KnowledgeBase
    from src.retrieval.dense_retriever  import DenseRetriever
    from src.retrieval.sparse_retriever import SparseRetriever
    from src.retrieval.hybrid_retriever import HybridRetriever

    kb     = KnowledgeBase()
    dense  = DenseRetriever(kb)
    sparse = SparseRetriever(kb)
    hybrid = HybridRetriever(kb)

    test_retriever("Dense  (FAISS)",      dense.retrieve)
    test_retriever("Sparse (BM25)",       sparse.retrieve)
    test_retriever("Hybrid (FAISS+BM25)", hybrid.retrieve)
    print("\n✅ All retriever tests passed")
