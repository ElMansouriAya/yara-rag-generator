"""
Evaluation metrics — complete suite for YARA RAG benchmarking.

Metrics: BLEU, ROUGE-L, Semantic Similarity, P@k, MRR,
         YARA Valid, Syntax Score, Hallucination Score.
"""

import numpy as np
from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
from rouge_score import rouge_scorer
from sentence_transformers import SentenceTransformer, util

from src.rag.evaluation.yara_validator import validate
from src.rag.evaluation.hallucination  import compute_hallucination_score
from src.rag.utils.config              import EMBEDDING_MODEL

_embedder = None

def _get_embedder():
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer(EMBEDDING_MODEL)
    return _embedder


def bleu(reference: str, hypothesis: str) -> float:
    ref = reference.lower().split()
    hyp = hypothesis.lower().split()
    return round(sentence_bleu([ref], hyp, smoothing_function=SmoothingFunction().method1), 4)


def rouge_l(reference: str, hypothesis: str) -> float:
    scorer = rouge_scorer.RougeScorer(["rougeL"], use_stemmer=False)
    return round(scorer.score(reference, hypothesis)["rougeL"].fmeasure, 4)


def semantic_similarity(reference: str, hypothesis: str) -> float:
    e = _get_embedder()
    return round(float(util.cos_sim(e.encode(reference, convert_to_tensor=True),
                                    e.encode(hypothesis, convert_to_tensor=True))), 4)


def precision_at_k(retrieved_docs: list, query: str, k: int = 3) -> float:
    keywords = set(query.lower().split())
    hits = sum(1 for doc in retrieved_docs[:k]
               if any(kw in (doc.get("description","")+" "+doc.get("embedding_text","")).lower()
                      for kw in keywords))
    return round(hits / k, 4)


def mean_reciprocal_rank(retrieved_docs: list, query: str) -> float:
    keywords = set(query.lower().split())
    for rank, doc in enumerate(retrieved_docs, 1):
        if any(kw in (doc.get("description","")+" "+doc.get("embedding_text","")).lower()
               for kw in keywords):
            return round(1 / rank, 4)
    return 0.0


def evaluate_result(query: str, generated: str,
                    reference: str, retrieved: list) -> dict:
    yv = validate(generated)
    hc = compute_hallucination_score(generated)
    return {
        "bleu"               : bleu(reference, generated),
        "rouge_l"            : rouge_l(reference, generated),
        "semantic_similarity": semantic_similarity(reference, generated),
        "yara_valid"         : int(yv["is_valid"]),
        "syntax_score"       : yv["syntax_score"],
        "num_strings"        : yv["num_strings"],
        "has_meta"           : int(yv["has_meta"]),
        "has_condition"      : int(yv["has_condition"]),
        "hallucination_score": hc["score"],
        "precision_at_k"     : precision_at_k(retrieved, query),
        "mrr"                : mean_reciprocal_rank(retrieved, query),
    }


def average_metrics(results: list) -> dict:
    if not results:
        return {}
    return {k: round(float(np.mean([r[k] for r in results])), 4)
            for k in results[0]}
