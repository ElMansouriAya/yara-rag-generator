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
├── README.md
├── requirements.txt
├── .gitignore
│
├── data/
│
├── notebooks/
│
├── src/
│   ├── preprocessing/
│   ├── retrieval/
│   ├── rag/
│   └── dashboard/
│
└── reports/
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