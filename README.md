# YARA Rule Generation using NLP and RAG

## Project Overview

This project aims to develop an intelligent system capable of generating YARA rules from natural language descriptions using a Retrieval-Augmented Generation (RAG) architecture.

The objective is to assist cybersecurity analysts in creating YARA detection rules by leveraging:

- Natural Language Processing (NLP)
- Semantic Retrieval
- Large Language Models (LLMs)
- Retrieval-Augmented Generation (RAG)

---

## Project Objectives

- Build a custom cybersecurity knowledge base
- Extract and process information from technical documents
- Implement a retrieval module to find relevant information
- Generate YARA rules from natural language descriptions
- Explain generated rules
- Evaluate retrieval and generation quality
- Provide a web dashboard for user interaction

---

## Project Architecture

```text
User Query
    ↓
NLP Processing
    ↓
Retrieval Module
    ↓
Context Enrichment
    ↓
LLM Generation
    ↓
YARA Rule Output
```

## Repository Structure
```
yara-rag-generator/
│
├── api.py                          ← PUBLIC API for Dashboard team
├── run_benchmark.py                ← benchmark script (all modes × all models)
├── run_preprocessing.py            ← processing script 
├── rebuild_indexes.py              ← Force rebuild FAISS + BM25 indexes
├── DASHBOARD_GUIDE.md              ← Dashboard integration guide
├── requirements.txt
├── .gitignore
│
├── data/
│   ├── raw/                        ← PDFs (gitignored)
│   ├── dataset_yara_mvp.json              ← dev/testing (32 records)
│   ├── processed/
│   │   └── filtered/
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
│       ├── preprocessing/
│       │   ├── document_loader.py      → Lecture multi-format (PDF, .yar, .json, .csv, .html)
│       │   ├── text_cleaner.py         → Nettoyage du texte brut
│       │   ├── entity_extractor.py     → Extraction NLP des entités
│       │   ├── source_adapter.py       → Adaptation selon le type de source
│       │   ├── schema_builder.py       → Construction des records JSON
│       │   ├── embedding_text_gen.py   → Génération du champ embedding_text
│       │   └── knowledge_base.py       → Orchestrateur du pipeline
│       ├── validation/
│       │   └── data_quality_filter.py  → Filtrage qualité + corrections
│       ├── augmentation/
│       │   └── synthetic_data_generator.py → Génération de données synthétiques 
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

## Knowledge Base Schema

The knowledge base is built from cybersecurity reports, YARA documentation, and malware analysis documents.

Each record follows the structure below:

```json
{
  "id": "RAN-001",
  "description": "Ransomware encrypting files using AES-256",
  "malware_family": "LockBit",
  "malware_type": "ransomware",
  "behavior_summary": [
    "file encryption",
    "AES usage",
    "shadow copy deletion"
  ],
  "attack_stage": "post-exploitation",
  "ioc": [
    ".locked",
    "ransom_note.txt",
    "vssadmin delete shadows"
  ],
  "yara_rule": "rule LockBit_AES { ... }",
  "rule_conditions": [
    "filesize",
    "strings",
    "entropy"
  ],
  "strings_or_patterns": [
    "AES",
    "encrypt",
    "ransom",
    "vssadmin"
  ],
  "source_document": "cisa_lockbit_report.pdf",
  "confidence": "high",
  "notes_on_fp": "May match VeraCrypt if entropy alone is used",
  "language": "en",
  "embedding_text": "Ransomware encrypting files using AES-256 file encryption AES usage shadow copy deletion .locked ransom_note.txt vssadmin delete shadows LockBit ransomware"
}
```

### Field Description

| Field | Description |
|---------|-------------|
| id | Unique sample identifier |
| description | Natural language malware description |
| malware_family | Malware family name |
| malware_type | Malware category |
| behavior_summary | Key observed behaviors |
| attack_stage | Attack lifecycle stage |
| ioc | Indicators of compromise |
| yara_rule | Associated YARA rule |
| rule_conditions | Main rule conditions |
| strings_or_patterns | Relevant strings and patterns |
| source_document | Source report or document |
| confidence | Confidence level |
| notes_on_fp | Potential false positive notes |


## Documentation Sources

Raw documents used to build the knowledge base:

Google Drive:
https://drive.google.com/drive/folders/17e_BJe1J0ePQg_fJatixlJPP7ThXh6nm?usp=sharing

Contents:
- Malware reports
- YARA documentation
- Threat intelligence reports
- Research articles


## Academic Context

Module: Natural Language Processing (NLP)

Project Topic: Automatic YARA Rule Generation using Retrieval-Augmented Generation (RAG)

Academic Year: 2025-2026