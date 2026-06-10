"""
Fusion Module — explicit score fusion for Hybrid RAG.

Combines dense (FAISS) and sparse (BM25) scores into a single
hybrid score using weighted linear interpolation.

    hybrid_score = alpha * dense_score + (1 - alpha) * sparse_score

Alpha tuning:
    alpha = 0.7  → favor dense  (better for vague/semantic queries)
    alpha = 0.5  → balanced     (default)
    alpha = 0.3  → favor sparse (better for exact technical keywords)
"""

import numpy as np


def normalize(scores: np.ndarray) -> np.ndarray:
    """Normalize scores to [0, 1] range."""
    min_s, max_s = scores.min(), scores.max()
    if max_s - min_s == 0:
        return np.zeros_like(scores)
    return (scores - min_s) / (max_s - min_s)


def fuse(dense_scores: np.ndarray,
         sparse_scores: np.ndarray,
         alpha: float = 0.5) -> np.ndarray:
    """
    Fuse dense and sparse scores into hybrid scores.

    Args:
        dense_scores  : raw scores from FAISS (higher = more similar)
        sparse_scores : raw scores from BM25
        alpha         : weight for dense scores (0.0 to 1.0)

    Returns:
        np.ndarray: hybrid scores, same length as inputs
    """
    assert 0.0 <= alpha <= 1.0, "alpha must be between 0 and 1"
    assert len(dense_scores) == len(sparse_scores), "score arrays must have same length"

    dense_norm  = normalize(dense_scores)
    sparse_norm = normalize(sparse_scores)

    return alpha * dense_norm + (1 - alpha) * sparse_norm
