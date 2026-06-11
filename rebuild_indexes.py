"""
rebuild_indexes.py — Force rebuild FAISS + BM25 indexes.

Use this script when:
    - You receive a new dataset from the NLP team
    - You change the embedding model
    - You want to clear the cache

Usage:
    python rebuild_indexes.py
    python rebuild_indexes.py --dataset data/processed/dataset_yara_mvp.json
"""

import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.rag.kb.knowledge_base import KnowledgeBase
from src.rag.utils.config      import INDEX_DIR, DATASET_PATH
import shutil


def main():
    parser = argparse.ArgumentParser(description="Rebuild FAISS + BM25 indexes")
    parser.add_argument("--dataset", type=str, default=None,
                        help="Dataset path (default: production dataset)")
    args = parser.parse_args()

    dataset = args.dataset or DATASET_PATH
    print(f"\n[rebuild] Dataset  : {dataset}")
    print(f"[rebuild] Index dir: {INDEX_DIR}")

    # Clear existing indexes
    if os.path.exists(INDEX_DIR):
        for f in os.listdir(INDEX_DIR):
            os.remove(os.path.join(INDEX_DIR, f))
        print("[rebuild] Cleared existing indexes")

    # Rebuild
    kb = KnowledgeBase(dataset)
    print(f"\n[rebuild] Done — {len(kb)} documents indexed")
    print(f"[rebuild] Files saved:")
    for f in os.listdir(INDEX_DIR):
        size = os.path.getsize(os.path.join(INDEX_DIR, f))
        print(f"  {f:30} {size/1024:.1f} KB")


if __name__ == "__main__":
    main()
