"""Utility functions shared across modules."""
import json, os
from src.rag.utils.config import DATASET_PATH


def load_dataset(path: str = None) -> list[dict]:
    """Load YARA dataset from JSON file."""
    p = path or DATASET_PATH
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"[Dataset] Loaded {len(data)} records from {os.path.basename(p)}")
    return data


def get_embedding_texts(data: list[dict]) -> list[str]:
    """
    Extract text for embedding.
    Uses embedding_text field (pre-computed by NLP team).
    Falls back to description + behaviors + ioc if missing.
    """
    texts = []
    for entry in data:
        if entry.get("embedding_text"):
            texts.append(entry["embedding_text"])
        else:
            parts = [entry.get("description", "")]
            parts += entry.get("behavior_summary", [])
            parts += entry.get("ioc", [])
            texts.append(" ".join(parts))
    return texts


def format_doc(entry: dict, score: float) -> dict:
    """Normalize a document to standard retrieval output format."""
    return {
        "id"              : entry.get("id", ""),
        "description"     : entry.get("description", ""),
        "malware_type"    : entry.get("malware_type", ""),
        "malware_family"  : entry.get("malware_family", ""),
        "yara_rule"       : entry.get("yara_rule", ""),
        "ioc"             : entry.get("ioc", []),
        "behavior_summary": entry.get("behavior_summary", []),
        "attack_stage"    : entry.get("attack_stage", ""),
        "embedding_text"  : entry.get("embedding_text", ""),
        "source_type"     : entry.get("source_type", ""),
        "confidence"      : entry.get("confidence", ""),
        "notes_on_fp"     : entry.get("notes_on_fp", ""),
        "score"           : round(float(score), 4),
    }


def filter_by_confidence(data: list[dict],
                          levels: list[str] = None) -> list[dict]:
    """
    Filter dataset by confidence level.

    Args:
        data  : full dataset
        levels: list of levels to keep, default ["high", "medium"]

    Returns:
        filtered list
    """
    levels = levels or ["high", "medium"]
    return [r for r in data if r.get("confidence") in levels]


def filter_synthetic(data: list[dict],
                     include: bool = True) -> list[dict]:
    """
    Filter synthetic records.

    Args:
        data   : full dataset
        include: True = keep synthetics, False = exclude them

    Returns:
        filtered list
    """
    if include:
        return data
    return [r for r in data if not r.get("id", "").startswith("SYN-")]


def get_dataset_stats(data: list[dict]) -> dict:
    """Return basic statistics about the dataset."""
    types      = {}
    families   = {}
    confidence = {}
    synthetic  = 0

    for r in data:
        t = r.get("malware_type", "unknown")
        f = r.get("malware_family", "unknown")
        c = r.get("confidence", "unknown")
        types[t]      = types.get(t, 0) + 1
        families[f]   = families.get(f, 0) + 1
        confidence[c] = confidence.get(c, 0) + 1
        if r.get("id", "").startswith("SYN-"):
            synthetic += 1

    return {
        "total"     : len(data),
        "synthetic" : synthetic,
        "original"  : len(data) - synthetic,
        "by_type"   : dict(sorted(types.items(), key=lambda x: -x[1])),
        "by_confidence": confidence,
        "top_families" : dict(sorted(families.items(), key=lambda x: -x[1])[:10]),
    }
