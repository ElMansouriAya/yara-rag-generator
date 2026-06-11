# RAG Pipeline & LLM Generation — Technical Documentation

**Project:** Automatic YARA Rule Generation using NLP and RAG  
**RAG membre | Git Branch:** `feature/rag`  
**Public API file:** `api.py`  

---

## Table of Contents

## Table of Contents

1. Overview
2. What the RAG team produced
3. Repository structure
4. Index Management
5. Public API — complete reference
6. Dataset integration (from NLP team)
7. RAG architectures — how they work
8. Agents — roles and interactions
9. LLM models — comparison and usage
10. Evaluation metrics — complete list
11. How to run the benchmark
12. Integration guide for Dashboard team
13. Known limitations
14. Full usage examples

---

## 1. Overview

The RAG module sits between the NLP Knowledge Base and the Dashboard interface.

```
[NLP Team]                    [RAG Team]                  [Dashboard Team]
dataset_production_enriched.json
        ↓
  KnowledgeBase          ← loads dataset, builds FAISS + BM25 indexes
        ↓
  Retrievers             ← Dense / Sparse / Hybrid
        ↓
  Agents                 ← QueryAnalyzer / RetrievalAgent / ValidationAgent
        ↓
  LLM Generation         ← Qwen / Mistral / Flan-T5
        ↓
  YARA Rule + Explanation
        ↓
                                                    api.py ← Dashboard entry point
```

**Responsibilities**

| Team | Responsibility |
|---|---|
| NLP | PDF extraction, dataset construction, synthetic enrichment |
| RAG (this doc) | Vectorization, retrieval, generation, evaluation |
| Dashboard | interface, visualization |

---

## 2. What the RAG team produced

### Files delivered

```
api.py                     ← PUBLIC API — Dashboard entry point
run_benchmark.py           ← standalone benchmark script
DASHBOARD_GUIDE.md         ← integration guide for Dashboard team
src/rag/                   ← all RAG source code
results/                   ← benchmark outputs (JSON, CSV, TXT)
```

### Pipeline summary

```
dataset_production_enriched.json   (3046 records from NLP team)
        ↓  KnowledgeBase
FAISS index + BM25 index           (built once, shared across retrievers)
        ↓
Query Analysis                     (QueryAnalyzer — no LLM, pattern matching)
        ↓
Retrieval Decision                 (RetrievalAgent — selects best retriever)
        ↓
Dense / Sparse / Hybrid retrieval  (top-k documents)
        ↓
Prompt Engineering                 (build_prompt — injects IOC, behaviors, examples)
        ↓
LLM Generation                     (Qwen / Mistral / Flan-T5)
        ↓
Validation Loop                    (ValidationAgent — retry if invalid)
        ↓
YARA Rule + Metrics + Explanation
```

---

## 3. Repository Structure

```
yara-rag-generator/
│
├── api.py                          ← PUBLIC API for Dashboard team
├── run_benchmark.py                ← benchmark script (all modes × all models)
├── DASHBOARD_GUIDE.md              ← Dashboard integration guide
├── requirements.txt
├── .gitignore
│
├── data/
│   ├── raw/                        ← PDFs (gitignored)
│   ├── dataset_yara_mvp.json              ← dev/testing (32 records)
│   ├── processed/
│   │   ├── filtered/
│   │       └── dataset_production_enriched.json   ← NLP team delivery (3046 records)
│   └── indexes/                    ← FAISS + BM25 saved indexes (gitignored)
│       ├── faiss_index.bin         ← FAISS vector database (~4.7 MB)
│       ├── bm25_index.pkl          ← BM25 sparse index (~1.5 MB)
│       ├── metadata.json           ← hash + config + build date
│       └── embeddings.npy          ← vector cache (optional, auto-generated)
│
├── src/
│   ├── rag/                        ← RAG team code (feature/rag branch)
│   │   ├── kb/
│   │   │   └── knowledge_base.py   ← loads dataset, builds FAISS + BM25
│   │   ├── retrieval/
│   │   │   ├── dense_retriever.py  ← FAISS semantic search
│   │   │   ├── sparse_retriever.py ← BM25 keyword search
│   │   │   ├── hybrid_retriever.py ← FAISS + BM25 fusion
│   │   │   └── fusion.py           ← explicit score fusion (alpha-weighted)
│   │   ├── agents/
│   │   │   ├── query_analyzer.py   ← analyze query → metadata (no LLM)
│   │   │   ├── retrieval_agent.py  ← select retriever → retrieve docs
│   │   │   └── validation_agent.py ← validate YARA rule → retry decision
│   │   ├── generation/
│   │   │   ├── prompt_builder.py   ← enriched prompts (RAG / baseline / explain)
│   │   │   ├── llm_qwen.py         ← Qwen2.5-0.5B-Instruct wrapper
│   │   │   ├── llm_mistral.py      ← Mistral-7B-Instruct (4-bit) wrapper
│   │   │   ├── llm_flan.py         ← Flan-T5-base wrapper
│   │   │   └── postprocessor.py    ← extract YARA block from LLM output
│   │   ├── pipeline/
│   │   │   ├── rag_classic.py      ← Classic RAG (dense + LLM)
│   │   │   ├── rag_hybrid.py       ← Hybrid RAG (FAISS+BM25 + LLM)
│   │   │   ├── rag_agentic.py      ← Agentic RAG (full agent loop)
│   │   │   └── pipeline.py         ← orchestrator + set_llm() + explain()
│   │   └── evaluation/
│   │       ├── metrics.py          ← BLEU, ROUGE-L, Sem.Sim, P@k, MRR
│   │       ├── yara_validator.py   ← structural YARA validation
│   │       └── hallucination.py    ← detect invented YARA constructs
│   │
│   └── nlp/                        ← NLP team code (feature/nlp branch)
│       └── README.md
│
├── interface/                      ← Dashboard team code (feature/dashboard branch)
│   ├── app.py
│   └── components/
│
├── tests/
│   ├── test_retrieval.py
│   ├── test_agents.py
│   └── test_yara_validator.py
│
└── results/                        ← benchmark outputs
    ├── benchmark_YYYYMMDD.json
    ├── benchmark_summary_YYYYMMDD.csv
    └── benchmark_report_YYYYMMDD.txt
```

---

---

## 4. Index Management ← NEW SECTION

### Automatic Detection

The system automatically handles index state:

| Scenario | Behavior | Time |
|----------|----------|------|
| First run | Build FAISS + BM25 indexes | ~30s |
| Subsequent runs | Load from disk | ~1s |
| Dataset changed | Detect via hash, auto-rebuild | ~30s |
| Corrupted index | Rebuild automatically | ~30s |

### Index Files 

data/indexes/
├── faiss_index.bin      ← FAISS vector database (~4.7 MB for 3046 docs)
├── bm25_index.pkl       ← BM25 sparse index (~1.5 MB)
├── metadata.json        ← Hash + config + build date
└── embeddings.npy       ← Vector cache (optional, auto-generated)

### Manual Rebuild

Force rebuild after dataset updates:

```bash
python rebuild_indexes.py
```

With custom dataset:
```bash
python rebuild_indexes.py --dataset data/processed/filtered/dataset_production_enriched.json
```

### Expected output:

[rebuild] Dataset  : data/processed/filtered/dataset_production_enriched.json
[rebuild] Index dir: data/indexes/
[rebuild] Cleared existing indexes
[rebuild] Done — 3166 documents indexed
[rebuild] Files saved:
  bm25_index.pkl                 1533.6 KB
  faiss_index.bin                4749.0 KB
  metadata.json                  0.5 KB

### Hash-based Change Detection
The system detects dataset changes via MD5 hash:
dataset_path + num_docs + first_doc_id
If hash mismatch → automatic rebuild
If model changed → automatic rebuild

## 5. Public API — Complete Reference

The Dashboard team uses **only** `api.py`. No other imports needed.

```python
from api import YARARAGAPI
api = YARARAGAPI()
```

### Constructor

```python
YARARAGAPI(model="qwen", dataset_path=None)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `model` | str | `"qwen"` | LLM to use: `"qwen"` / `"flan"` / `"mistral"` |
| `dataset_path` | str | None | Custom dataset path (uses production dataset by default) |

---

### `api.generate(query, mode=None)`

Generate a YARA rule from a threat description.

```python
result = api.generate(
    query = "Ransomware encrypting files with AES and deleting shadow copies",
    mode  = "agentic"
)
```

**Returns:**
```python
{
    "query"         : str,    # original query
    "mode"          : str,    # mode used
    "yara_rule"     : str,    # generated YARA rule
    "valid"         : bool,   # structural validity
    "syntax_score"  : float,  # 0.0 to 1.0
    "sources"       : list,   # retrieved documents used
    "iterations"    : int,    # agentic only: number of iterations
    "retriever_used": str,    # agentic only: dense/sparse/hybrid
    "model"         : str,    # LLM used
}
```

---

### `api.explain(yara_rule)`

Generate a natural language explanation of a YARA rule.

```python
explanation = api.explain(result["yara_rule"])
# → "This rule detects ransomware behavior by looking for AES encryption..."
```

**Returns:** `str` — plain English explanation

---

### `api.search(query, k=5)`

Search the knowledge base without generating a rule.

```python
docs = api.search("Ransomware with AES encryption", k=5)
```

**Returns:** `list[dict]` — each dict contains:
```python
{
    "id"            : str,   # e.g. "RAN-001"
    "description"   : str,
    "malware_type"  : str,
    "malware_family": str,
    "yara_rule"     : str,
    "score"         : float, # relevance score 0.0-1.0
    "confidence"    : str,   # "high" or "medium"
    "source_type"   : str,   # "malware_report", "yara_rule", "synthetic"...
}
```

---

### `api.benchmark(queries, references)`

Benchmark all 4 modes on a list of queries.

```python
report = api.benchmark(queries, references)
```

**Returns:**
```python
{
    "summary": {
        "agentic" : {"bleu": 0.x, "syntax_score": 0.x, "yara_valid": 0.x, ...},
        "hybrid"  : {...},
        "classic" : {...},
        "baseline": {...},
    },
    "per_query": [...],
    "model"    : str,
}
```

---

### `api.dataset_stats()`

Get knowledge base statistics.

```python
stats = api.dataset_stats()
# {
#   "total": 3046,
#   "synthetic": 431,
#   "original": 2615,
#   "by_type": {"trojan": 1390, "ransomware": 209, ...},
#   "by_confidence": {"high": 1453, "medium": 1593},
#   "top_families": {"Backdoor": 132, "Comment_Crew": 114, ...}
# }
```

---

### `api.use_model(model_name)`

Switch LLM without reloading the knowledge base.

```python
api.use_model("mistral")   # switch to Mistral-7B
api.use_model("flan")      # switch to Flan-T5
api.use_model("qwen")      # switch back to Qwen
```

---

### `api.use_mode(mode)`

Set the default RAG mode for all subsequent generate() calls.

```python
api.use_mode("hybrid")            # all generate() calls use hybrid
result = api.generate(query)      # uses hybrid
result = api.generate(query, mode="agentic")  # override for this call
```

---

## 6. Dataset Integration (from NLP team)

### File expected

```
data/processed/filtered/dataset_production_enriched.json
```

### Auto-detection

`config.py` automatically detects the production dataset:

```python
# Uses production dataset if present, falls back to MVP dataset (32 records)
DATASET_PATH = DATASET_PROD if os.path.exists(DATASET_PROD) else DATASET_MVP
```

### Key field used for embedding

The RAG system vectorizes the `embedding_text` field — pre-computed by the NLP
team and optimized for semantic retrieval. Do not change this.

### Filter options (advanced)

```python
from src.rag.utils.helpers import filter_by_confidence, filter_synthetic

# High confidence only (for critical few-shot examples)
gold = filter_by_confidence(data, levels=["high"])

# Exclude synthetic records (A/B testing)
original_only = filter_synthetic(data, include=False)
```

---

## 7. RAG Architectures

### Classic RAG
```
query → DenseRetriever (FAISS top-k) → prompt_builder → LLM → YARA rule
```
Simple and fast. Good baseline. Uses semantic similarity only.

---

### Hybrid RAG
```
query → DenseRetriever  → dense_scores
query → SparseRetriever → sparse_scores
        fusion.fuse(dense, sparse, alpha=0.5) → hybrid_scores → top-k
        → prompt_builder → LLM → YARA rule
```
Best for queries mixing semantic intent and exact technical keywords
(e.g. "AES", "vssadmin", "SSDT").

**Alpha parameter** in `config.py`:
- `alpha = 0.7` → favor dense (semantic queries)
- `alpha = 0.5` → balanced (default)
- `alpha = 0.3` → favor sparse (exact keyword queries)

---

### Agentic RAG
```
query
  → QueryAnalyzer        (pattern matching → malware_type, keywords, complexity)
  → RetrievalAgent       (select: dense / sparse / hybrid based on analysis)
  → prompt_builder       (enriched prompt with IOC + behaviors + examples)
  → LLM                  (generate YARA rule)
  → ValidationAgent      (structural check + hallucination detection)
  → [retry with refined query if invalid — max 2 iterations]
  → final YARA rule
```
Most robust. Self-corrects invalid rules. Recommended for production.

---

### Baseline (no RAG)
```
query → prompt_builder (no context) → LLM → YARA rule
```
Used for comparison only. Produces hallucinations and invalid syntax.

---

## 8. Agents — Roles and Interactions

### QueryAnalyzer
- **Input:** `query: str`
- **Output:** `{ malware_type, keywords, complexity, suggested_retriever }`
- **Logic:** keyword pattern matching on 10 malware types — no LLM
- **Why no LLM:** fast, deterministic, no latency

### RetrievalAgent
- **Input:** query + QueryAnalyzer output
- **Output:** `{ docs, retriever_used, decision_reason }`
- **Logic:**
  - 2+ exact technical terms → SparseRetriever (BM25)
  - Long semantic query (>12 words) → DenseRetriever (FAISS)
  - Default → HybridRetriever

### ValidationAgent
- **Input:** `yara_rule, iteration, max_iterations`
- **Output:** `{ is_valid, should_retry, reason, refined_suffix }`
- **Checks:**
  - Structural: `rule`, `strings:`, `condition:`, `{}`
  - Hallucinations: fake functions like `deleteshadowcopy()`
  - Retry threshold: hallucination_score > 0.3

---

## 9. LLM Models

| Model | Size | VRAM | Speed | Quality | Use case |
|---|---|---|---|---|---|
| `qwen` — Qwen2.5-0.5B-Instruct | 0.5B | ~2GB | Fast | Good | Default, Colab free |
| `flan` — Flan-T5-base | 250M | ~1GB | Very fast | Lower | Lightweight benchmark |
| `mistral` — Mistral-7B-Instruct v0.3 | 7B (4-bit) | ~6GB | Slow | Best | Colab Pro / local GPU |

**Switching models at runtime:**
```python
api.use_model("mistral")   # no KB reload
```

---

## 10. Evaluation Metrics

| Metric | Category | What it measures |
|---|---|---|
| `bleu` | Text similarity | N-gram overlap with reference rule |
| `rouge_l` | Text similarity | Longest common subsequence |
| `semantic_similarity` | Text similarity | Cosine similarity of sentence embeddings |
| `yara_valid` | YARA quality | 1 if rule has rule + strings: + condition: + {} |
| `syntax_score` | YARA quality | Weighted structural score 0.0-1.0 |
| `num_strings` | YARA quality | Number of $variables in the rule |
| `has_meta` | YARA quality | 1 if meta: section present |
| `has_condition` | YARA quality | 1 if condition: section present |
| `hallucination_score` | Hallucination | 0.0=clean, 1.0=heavy hallucination |
| `precision_at_k` | Retrieval | Proportion of relevant docs in top-k |
| `mrr` | Retrieval | Mean Reciprocal Rank of first relevant doc |

**Syntax score weights:**
```
rule keyword   × 0.30
strings:       × 0.25
condition:     × 0.25
meta:          × 0.10
{  }           × 0.10
```

---

## 11. Running the Benchmark

### Quick start (Qwen only)
```bash
python run_benchmark.py
```

### All models
```bash
python run_benchmark.py --models all
```

### Specific models
```bash
python run_benchmark.py --models qwen flan
```

### Custom output directory
```bash
python run_benchmark.py --models qwen --output results/
```

### Silent mode (no per-rule output)
```bash
python run_benchmark.py --quiet
```

### Output files generated in `results/`

| File | Content |
|---|---|
| `benchmark_YYYYMMDD.json` | Full raw results |
| `benchmark_summary_YYYYMMDD.csv` | Metrics table (open in Excel) |
| `benchmark_report_YYYYMMDD.txt` | Human-readable report |

---

## 12. Integration Guide for Dashboard Team

See `DASHBOARD_GUIDE.md` for the complete guide with Gradio examples.

**Single import:**
```python
from api import YARARAGAPI
api = YARARAGAPI()
```

**Key methods:**

| Method | Purpose |
|---|---|
| `api.generate(query, mode)` | Generate YARA rule |
| `api.explain(rule)` | Natural language explanation |
| `api.search(query, k)` | Search KB without generating |
| `api.benchmark(queries, refs)` | Compare all modes |
| `api.dataset_stats()` | KB statistics |
| `api.use_model("mistral")` | Switch LLM |
| `api.use_mode("hybrid")` | Switch default mode |

---

## 13. Known Limitations

| Issue | Impact | Notes |
|---|---|---|
| `filesize` values invented | Low | Model generates arbitrary values (e.g. `> 500MB`). Prompt engineering partially mitigates this. |
| BLEU scores low (0.01-0.12) | None | Expected for code generation — Syntax + SemanticSim are the relevant metrics. |
| Classic/Hybrid may retrieve same doc repeatedly | Low | Small dataset effect. Resolved with production dataset (3046 records). |
| Mistral requires 4-bit quantization | Medium | Needs `bitsandbytes`. Not tested on Colab free tier — use Colab Pro or local GPU. |
| `$size = filesize` invalid | Low | Hybrid occasionally generates invalid string assignments. Post-processor catches most cases. |

---

## 14. Full Usage Examples

### Example 1 — Basic generation

```python
from api import YARARAGAPI

api    = YARARAGAPI(model="qwen")
result = api.generate(
    "Ransomware encrypting files with AES and deleting shadow copies",
    mode="agentic"
)

print(result["yara_rule"])
print(f"Valid: {result['valid']} | Score: {result['syntax_score']}")
print(f"Sources: {[s['id'] for s in result['sources']]}")
```

---

### Example 2 — Generate + explain

```python
result      = api.generate("Worm spreading via SMB network shares")
explanation = api.explain(result["yara_rule"])

print(result["yara_rule"])
print("---")
print(explanation)
```

---

### Example 3 — Switch model mid-session

```python
api = YARARAGAPI(model="qwen")

# Qwen result
r1 = api.generate("Backdoor using DNS tunneling", mode="hybrid")

# Switch to Flan (no KB reload)
api.use_model("flan")
r2 = api.generate("Backdoor using DNS tunneling", mode="hybrid")

print("Qwen  :", r1["yara_rule"][:100])
print("Flan  :", r2["yara_rule"][:100])
```

---

### Example 4 — Switch mode mid-session

```python
api = YARARAGAPI()

api.use_mode("hybrid")
r1 = api.generate("Cryptominer using XMRig")   # uses hybrid

api.use_mode("agentic")
r2 = api.generate("Cryptominer using XMRig")   # uses agentic

# Override for a single call
r3 = api.generate("Cryptominer using XMRig", mode="baseline")
```

---

### Example 5 — Full benchmark

```python
from api import YARARAGAPI

api = YARARAGAPI(model="qwen")

queries = [
    "Ransomware encrypting files with AES",
    "Keylogger with FTP exfiltration",
    "Worm spreading via SMB",
]
references = [
    "rule AES_Ransomware { strings: $a=\"AES\" nocase condition: $a }",
    "rule Keylogger { strings: $a=\"SetWindowsHookEx\" nocase condition: $a }",
    "rule SMB_Worm { strings: $a=\"NetShareEnum\" nocase condition: $a }",
]

report = api.benchmark(queries, references)

import pandas as pd
df = pd.DataFrame(report["summary"]).T
print(df[["bleu","syntax_score","yara_valid","hallucination_score"]])
```

---

### Example 6 — Dataset exploration

```python
api   = YARARAGAPI()
stats = api.dataset_stats()

print(f"Total records : {stats['total']}")
print(f"Synthetic     : {stats['synthetic']}")
print(f"By type       : {stats['by_type']}")

# Search for relevant examples
docs = api.search("process injection via CreateRemoteThread", k=5)
for d in docs:
    print(f"[{d['id']}] {d['malware_type']} | score={d['score']:.3f}")
    print(f"  {d['description'][:80]}...")
```

---

*RAG Membre | Master IASD 2026 | FST Tanger | Pr. Ikram Benabdelouahab*
