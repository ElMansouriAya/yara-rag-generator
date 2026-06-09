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


# NLP Pipeline & Knowledge Base — Documentation technique
## Projet : Automatic YARA Rule Generation using NLP and RAG

**Équipe NLP** | Branche Git : `feature/nlp`  
**Fichier livré à l'équipe RAG** : `dataset_production_enriched.json`

---

## Table des matières

1. [Vue d'ensemble du projet](#1-vue-densemble-du-projet)
2. [Ce que l'équipe NLP a produit](#2-ce-que-léquipe-nlp-a-produit)
3. [Schéma JSON — explication de chaque champ](#3-schéma-json--explication-de-chaque-champ)
4. [Statistiques du dataset final](#4-statistiques-du-dataset-final)
5. [Architecture du pipeline NLP](#5-architecture-du-pipeline-nlp)
6. [Les 4 étapes du pipeline](#6-les-4-étapes-du-pipeline)
7. [Données synthétiques — comment et pourquoi](#7-données-synthétiques--comment-et-pourquoi)
8. [Champ `embedding_text` — ce que le RAG doit savoir](#8-champ-embedding_text--ce-que-le-rag-doit-savoir)
9. [Champ `yara_rule` — format et contenu](#9-champ-yara_rule--format-et-contenu)
10. [Niveaux de confiance — comment les utiliser](#10-niveaux-de-confiance--comment-les-utiliser)
11. [Records synthétiques — comment les identifier](#11-records-synthétiques--comment-les-identifier)
12. [Limites connues et points d'attention](#12-limites-connues-et-points-dattention)
13. [Exemples de records complets](#13-exemples-de-records-complets)
14. [Fichiers livrés](#14-fichiers-livrés)

---

## 1. Vue d'ensemble du projet

Le projet vise à générer automatiquement des règles YARA depuis des descriptions en langage naturel de comportements de malwares.

### Architecture globale

```
Requête utilisateur
        ↓
  [Équipe NLP]  →  dataset_production_enriched.json
        ↓
  [Équipe RAG]  →  Retrieval (FAISS / BM25)
        ↓
  [Équipe LLM]  →  Génération de règle YARA
        ↓
    Règle YARA générée
```

### Responsabilités

| Équipe | Responsabilité |
|---|---|
| **NLP (ce document)** | Pipeline d'extraction, dataset structuré, données synthétiques |
| **RAG** | Vectorisation, indexation, retrieval sémantique |
| **LLM** | Génération de la règle YARA finale |
| **Dashboard** | Interface utilisateur |

**L'équipe RAG prend en entrée uniquement** : `dataset_production_enriched.json`

---

## 2. Ce que l'équipe NLP a produit

### Fichier principal livré

```
data/processed/filtered/dataset_production_enriched.json
```

C'est un tableau JSON de **3 046 records**. Chaque record représente un document de cybersécurité traité (rapport de malware, règle YARA, rapport de threat intelligence) transformé en entrée structurée.

### Pipeline en résumé

```
2850 documents bruts (PDFs, .yar, .json, .csv)
        ↓  document_loader.py
Extraction du texte brut
        ↓  text_cleaner.py
Nettoyage et normalisation
        ↓  entity_extractor.py
Extraction d'entités NLP (famille, type, IOCs, comportements...)
        ↓  schema_builder.py
Construction des records JSON (schéma fixe)
        ↓  embedding_text_gen.py
Génération du champ embedding_text
        ↓  data_quality_filter.py
Filtrage qualité + nettoyage IOCs + correction descriptions
        ↓  synthetic_data_generator.py
Enrichissement par données synthétiques (+431 records)
        ↓
dataset_production_enriched.json  ← LIVRÉ AU RAG
```

---

## 3. Schéma JSON — explication de chaque champ

Chaque record suit exactement ce schéma. **Ne pas modifier la structure** — elle a été validée en collaboration avec toutes les équipes.

```json
{
  "id": "RAN-001",
  "description": "...",
  "malware_family": "...",
  "malware_type": "...",
  "behavior_summary": [...],
  "attack_stage": "...",
  "ioc": [...],
  "yara_rule": "...",
  "rule_conditions": [...],
  "strings_or_patterns": [...],
  "source_document": "...",
  "confidence": "...",
  "notes_on_fp": "...",
  "language": "...",
  "embedding_text": "...",
  "source_type": "..."
}
```

### Description détaillée de chaque champ

#### `id` — Identifiant unique
- Format : `PREFIX-NNN` (ex: `RAN-001`, `TRJ-042`)
- Préfixes : `RAN`=ransomware, `TRJ`=trojan, `RTK`=rootkit, `SPY`=spyware, `WRM`=worm, `LDR`=loader, `EXP`=exploit, `BNK`=banker, `MIN`=miner, `GEN`=generic, `REC`=inconnu
- Records synthétiques : préfixe `SYN-` (ex: `SYN-RAN-001`, `SYN-TRJ-023`)
- **Usage RAG** : identifiant de référence pour les résultats de retrieval

---

#### `description` — Description textuelle du malware
- Texte en langage naturel décrivant le comportement principal
- Longueur : 50 à 600 caractères
- Source : bloc `meta: description` des règles YARA, ou premières phrases significatives du document source
- **Usage RAG** : inclus dans l'embedding, peut être affiché dans le contexte LLM

---

#### `malware_family` — Famille malware
- Exemples : `"LockBit"`, `"Emotet"`, `"CobaltStrike"`, `"WannaCry"`
- Valeur `"unknown"` si non identifiable (76.6% des records — voir section 12)
- **Usage RAG** : filtre optionnel pour le retrieval par famille spécifique

---

#### `malware_type` — Type/catégorie du malware
- Valeurs possibles :

| Valeur | Description |
|---|---|
| `ransomware` | Chiffre les fichiers, demande rançon |
| `trojan` | Accès distant, backdoor, RAT |
| `rootkit` | Se cache dans le kernel/UEFI |
| `spyware` | Collecte de données, keylogger |
| `worm` | Propagation automatique réseau |
| `loader` | Charge un second payload |
| `exploit` | Exploite une vulnérabilité |
| `banker` | Ciblage bancaire/financier |
| `miner` | Cryptominer |
| `generic` | Comportement suspect générique |
| `unknown` | Non classifiable |

- **Usage RAG** : filtrage par catégorie, important pour le prompt LLM

---

#### `behavior_summary` — Liste des comportements détectés
- Tableau de chaînes décrivant les actions malveillantes
- Exemples de valeurs :
  ```
  "file encryption", "shadow copy deletion", "process injection",
  "credential harvesting", "network communication", "data exfiltration",
  "lateral movement", "persistence via scheduled task", "shellcode execution",
  "anti-analysis", "anti-forensics", "bootkit/rootkit activity",
  "registry modification"
  ```
- Nombre : 1 à 11 comportements par record
- **Usage RAG** : champ clé pour le matching sémantique sur les requêtes comportementales. Exemple de requête : `"règle pour détecter le chiffrement de fichiers"` → match sur `"file encryption"`

---

#### `attack_stage` — Phase ATT&CK MITRE
- Valeurs possibles :
  ```
  initial-access, execution, persistence, privilege-escalation,
  defense-evasion, credential-access, discovery, lateral-movement,
  collection, command-and-control, exfiltration, impact,
  post-exploitation, unknown
  ```
- **Usage RAG** : contexte pour le LLM, peut aider à affiner la règle générée

---

#### `ioc` — Indicateurs de compromission
- Tableau de chaînes
- Types présents : adresses IP, domaines, hashes MD5/SHA256, chemins de fichiers suspects, clés de registre, noms de fichiers malveillants, commandes système
- Les IOCs légitimes (outils d'analyse, domaines éditeurs de sécurité) ont été filtrés
- Exemples :
  ```json
  ["99.124.22.1", "evil.malwar3.com", "vssadmin delete shadows",
   "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
   "C:\\Windows\\System32\\kerne132.dll"]
  ```
- **Usage RAG** : enrichit le contexte, peut être injecté dans le prompt LLM

---

#### `yara_rule` — Règle YARA complète
- Chaîne contenant la règle YARA brute (syntaxe standard)
- Présente dans 99.5% des records
- Peut contenir plusieurs règles concaténées (rares cas, signalé dans `notes_on_fp`)
- Format :
  ```yara
  rule RuleName {
      meta:
          description = "..."
          author = "..."
          date = "..."
      strings:
          $s1 = "..." ascii wide
          $s2 = { hex bytes }
      condition:
          any of them
  }
  ```
- **Usage RAG** : c'est la sortie cible. Le LLM doit générer quelque chose de similaire. Ces règles servent d'exemples few-shot.

---

#### `rule_conditions` — Conditions extraites de la règle YARA
- Tableau des conditions utilisées dans la règle
- Exemples : `["filesize", "any of them", "pe.imphash", "entropy", "uint16(0)"]`
- **Usage RAG** : aide le LLM à choisir les conditions appropriées

---

#### `strings_or_patterns` — Strings et patterns de la règle
- Tableau des chaînes caractéristiques extraites
- Peut contenir : chaînes ASCII, patterns hex, expressions régulières
- **Usage RAG** : contexte pour le LLM lors de la génération de strings YARA

---

#### `source_document` — Document source
- Nom du fichier original (PDF, .yar, .json...)
- Records synthétiques : `synthetic_variation`, `synthetic_cross_family`, `synthetic_mitre_attck`, `synthetic_template_*`
- **Usage RAG** : traçabilité, peut être affiché pour information

---

#### `confidence` — Niveau de confiance du record
- `"high"` : record fiable avec plusieurs champs renseignés et cohérents
- `"medium"` : record utilisable, quelques champs manquants
- Aucun record `"low"` dans le dataset de production (filtrés)
- Voir section 10 pour les critères de scoring
- **Usage RAG** : pondération optionnelle du score de retrieval

---

#### `notes_on_fp` — Notes sur les faux positifs
- Avertissements sur les risques de faux positifs de la règle
- Exemples :
  - `"May match legitimate encryption tools if entropy alone is used"`
  - `"Kernel-level hooks may match legitimate drivers"`
  - `"High FP rate on packed executables; use pe.imphash for precision"`
- **Usage RAG** : peut être injecté dans le prompt LLM pour affiner la règle générée

---

#### `language` — Langue du document source
- Valeur dominante : `"en"` (anglais)
- Détecté automatiquement avec `langdetect`
- **Usage RAG** : filtre optionnel

---

#### `embedding_text` — Texte optimisé pour la vectorisation
- **Champ le plus important pour le RAG**
- Texte concaténé et nettoyé, optimisé pour produire un bon vecteur d'embedding
- Construction : `description + famille×2 + type + noms_règles_YARA + comportements + attack_stage + IOCs_pertinents + patterns`
- Longueur moyenne : 352 caractères
- 0 record avec embedding < 80 caractères
- Voir section 8 pour les détails complets
- **Usage RAG** : c'est CE CHAMP que vous devez vectoriser (pas `description`, pas `yara_rule`)

---

#### `source_type` — Type de source du document
- Valeurs :

| Valeur | Signification |
|---|---|
| `yara_cybersecurity_rule` | Règle YARA cybersécurité (dossier rules-yara-cybersecurity) |
| `yara_rule` | Règle YARA générique (dossier rules, yara) |
| `yara_misc` | Règle YARA diverse |
| `malware_report` | Rapport d'analyse de malware (PDF) |
| `threat_intelligence` | Rapport de threat intelligence |
| `structured_data` | Données structurées (CSV/JSON) |
| `synthetic` | Record généré synthétiquement |

- **Usage RAG** : peut être utilisé pour pondérer différemment les sources (ex: malware_report > yara_misc)

---

## 4. Statistiques du dataset final

### Vue globale

| Métrique | Valeur |
|---|---|
| Total records | **3 046** |
| Records originaux | 2 615 (85.9%) |
| Records synthétiques | 431 (14.1%) |
| Avec règle YARA | 3 030 (99.5%) |
| Avec IOCs | 2 589 (85.0%) |
| Avec comportements | 2 648 (86.9%) |
| Famille connue | 1 018 (33.4%) |
| Famille inconnue | 2 028 (66.6%) |
| Confiance high | 1 453 (47.7%) |
| Confiance medium | 1 593 (52.3%) |
| Embedding moyen | 352 caractères |

### Distribution par type de malware

| Type | Count | % |
|---|---|---|
| trojan | 1 390 | 45.6% |
| exploit | 530 | 17.4% |
| unknown | 445 | 14.6% |
| ransomware | 209 | 6.9% |
| loader | 178 | 5.8% |
| generic | 145 | 4.8% |
| spyware | 60 | 2.0% |
| worm | 28 | 0.9% |
| rootkit | 23 | 0.8% |
| autres | 38 | 1.2% |

### Top 10 familles identifiées

| Famille | Count | Dont synthétique |
|---|---|---|
| Backdoor | 132 | 48 |
| Comment_Crew | 114 | 41 |
| Mimikatz | 28 | 11 |
| Turla | 21 | 5 |
| CozyBear | 19 | 7 |
| WannaCry | 19 | 9 |
| FancyBear | 18 | 4 |
| LockBit | 12 | 7 |
| Emotet | 11 | 9 |
| CobaltStrike | 15 | 8 |

---

## 5. Architecture du pipeline NLP

```
data/raw/
├── Rapports malware/          (PDFs)
├── rules/                     (fichiers .yar)
├── rules-yara-cybersecurity/  (fichiers .yar)
├── Threat intelligence et IOC/(PDFs, JSON)
├── yara/                      (fichiers .yar)
├── YARA csv-json/             (CSV, JSON)
└── YARA Documentations/       (PDFs)
        ↓
src/
├── preprocessing/
│   ├── document_loader.py      → Lecture multi-format (PDF, .yar, .json, .csv, .html)
│   ├── text_cleaner.py         → Nettoyage du texte brut
│   ├── entity_extractor.py     → Extraction NLP des entités
│   ├── source_adapter.py       → Adaptation selon le type de source
│   ├── schema_builder.py       → Construction des records JSON
│   ├── embedding_text_gen.py   → Génération du champ embedding_text
│   └── knowledge_base.py       → Orchestrateur du pipeline
├── validation/
│   └── data_quality_filter.py  → Filtrage qualité + corrections
└── augmentation/
    └── synthetic_data_generator.py → Génération de données synthétiques

data/processed/filtered/
├── dataset_production.json           → Dataset filtré (2615 records)
├── dataset_high_quality.json         → Records high confidence uniquement
├── dataset_rejected.json             → Records écartés (audit)
└── dataset_production_enriched.json  → FICHIER FINAL (3046 records)
```

---

## 6. Les 4 étapes du pipeline

### Étape 1 — Chargement des documents

**Script** : `document_loader.py`

Lit tous les fichiers des sous-dossiers de `data/raw/`. Formats supportés : PDF, `.yar`, `.yara`, `.json`, `.csv`, `.txt`, `.html`, `.md`.

Pour les PDFs : extraction via PyMuPDF (fallback pdfplumber).
Pour les YARA : lecture texte directe.
Pour les JSON/CSV : parsing structuré.

**Sortie** : liste de dicts avec `raw_text`, `filename`, `source_folder`, `doc_type`.

---

### Étape 2 — Nettoyage et extraction d'entités

**Scripts** : `text_cleaner.py`, `entity_extractor.py`, `source_adapter.py`

Le `text_cleaner` supprime :
- Artefacts PDF (`(cid:xxx)`, caractères de contrôle)
- Numéros de page, marqueurs TLP/CONFIDENTIAL
- Blocs hex non pertinents (> 30 octets consécutifs)

> **Important** : les URLs ne sont PAS supprimées car elles peuvent être des IOCs.

L'`entity_extractor` extrait via regex et dictionnaires :
- Famille malware : matching sur liste de 150+ familles connues + mapping APT
- Type malware : patterns dans nom de fichier et texte
- IOCs : IPs, domaines, hashes, chemins, clés de registre
- Comportements : matching sur dictionnaire de 50+ comportements
- Attack stage : mapping MITRE ATT&CK
- Règles YARA : extraction des blocs `rule { ... }`

Le `source_adapter` ajuste l'extraction selon le type de source (YARA vs PDF rapport).

---

### Étape 3 — Filtrage qualité

**Script** : `data_quality_filter.py`

Appliqué après le pipeline principal. 6 corrections automatiques :

1. **Nettoyage IOCs** : suppression des domaines d'outils d'analyse légitimes (114 domaines whitelistés : `virustotal.com`, `mandiant.com`, `sysinternals.com`, etc.)
2. **Correction famille** : détection des fausses familles dans les sources pédagogiques (< 2 occurrences = référence, pas le sujet du document)
3. **Correction description** : remplacement des tables des matières et listes par une description construite depuis les champs structurés ou le `meta:` YARA
4. **Re-génération embedding** : reconstruction depuis les champs corrigés
5. **Re-calcul confiance** : scoring repondéré
6. **Rejet** : records avec embedding < 80 chars, sans YARA + sans IOC + sans famille, ou documentation pure

**Résultat** : 2 844 → 2 615 records (229 rejetés).

---

### Étape 4 — Enrichissement synthétique

**Script** : `synthetic_data_generator.py`

4 stratégies de génération (voir section 7).

**Résultat** : 2 615 → 3 046 records (+431 synthétiques).

---

## 7. Données synthétiques — comment et pourquoi

### Pourquoi des données synthétiques ?

Le cahier des charges impose un enrichissement automatique du dataset. Les données synthétiques servent à :
- Augmenter la couverture des familles sous-représentées
- Couvrir des scénarios d'infection multi-étapes
- Ajouter des TTPs MITRE ATT&CK génériques
- Améliorer la robustesse du retrieval face à des requêtes variées

### Les 4 stratégies

#### Stratégie 1 — Variation sémantique (198 records)
Reformule les descriptions et comportements des meilleurs records existants.
- Source : records `confidence=high` avec famille connue
- Les comportements sont substitués par des synonymes cybersécurité réels
- Exemple : `"file encryption"` → `"AES file locking"` ou `"encrypts victim files"`
- `source_document` : `"synthetic_variation"`

#### Stratégie 2 — Combinaison cross-famille (149 records)
Simule des scénarios d'infection en chaîne réalistes.
- Exemple : `"QuasarRAT acting as initial loader delivering BabbleLoader payload"`
- Combine les comportements et IOCs de deux familles différentes
- L'attack_stage le plus avancé est retenu
- `source_document` : `"synthetic_cross_family"`

#### Stratégie 3 — Scénarios MITRE ATT&CK (40 records)
Génère des records basés sur 6 techniques ATT&CK réelles :
- Process hollowing (defense-evasion)
- Phishing macro VBA (initial-access)
- Registry run key (persistence)
- DNS tunneling (exfiltration)
- UAC bypass (privilege-escalation)
- HTTPS C2 beaconing (command-and-control)

Chaque record inclut une règle YARA avec les strings caractéristiques de la technique.
- `malware_family` : `"unknown"` (technique générique, sans famille spécifique)
- `source_document` : `"synthetic_mitre_attck"`

#### Stratégie 4 — Templates familles connues (44 records)
Records complets et précis pour 7 familles bien documentées :
`WannaCry`, `Emotet`, `CobaltStrike`, `Mimikatz`, `LockBit`, `Ryuk`, `TrickBot`
- Descriptions professionnelles basées sur la documentation publique
- Règles YARA avec les vraies strings caractéristiques
- `confidence` : `"high"`
- `source_document` : `"synthetic_template_<famille>"`

### Comment identifier les records synthétiques

```python
# Identifier tous les records synthétiques
synthetic = [r for r in records if r['id'].startswith('SYN-')]

# Ou par source_type
synthetic = [r for r in records if r.get('source_type') == 'synthetic']

# Ou par source_document
synthetic = [r for r in records if 'synthetic' in r.get('source_document', '')]
```

---

## 8. Champ `embedding_text` — ce que le RAG doit savoir

### C'est le champ à vectoriser

Le champ `embedding_text` est le seul champ à utiliser pour créer les vecteurs d'embedding. Il a été construit spécifiquement pour maximiser la qualité du retrieval sémantique.

### Construction du champ

```
embedding_text = description[:200]
              + famille × 2    (pondéré ×2 pour ancrer le retrieval)
              + type
              + noms des règles YARA (ancres sémantiques)
              + comportements[:5]
              + attack_stage
              + IOCs pertinents[:6]  (IPs, hashes, domaines suspects)
              + strings_or_patterns[:4]
```

Tout est en minuscules, les doublons sont supprimés, les espaces normalisés.

### Exemple concret

```json
"embedding_text": "wannacry ransomworm exploiting eternalblue ms17-010 for lateral
movement encrypts files with aes-128 and rsa-2048. wannacry wannacry ransomware
file encryption lateral movement shadow copy deletion network communication impact
tasksche.exe mssecsvc.exe wannadecryptor .wncry"
```

### Ce qu'il NE faut PAS vectoriser

| Champ | Pourquoi ne pas vectoriser |
|---|---|
| `description` seule | Moins complète que `embedding_text` |
| `yara_rule` | Syntaxe technique, bruit pour l'embedding |
| `ioc` brut | Trop de faux IOCs sans le filtre |
| `source_document` | Nom de fichier, non sémantique |

### Recommandation de modèle d'embedding

Pour les règles YARA et le vocabulaire cybersécurité, nous recommandons :
- `sentence-transformers/all-MiniLM-L6-v2` (rapide, bon pour commencer)
- `sentence-transformers/all-mpnet-base-v2` (meilleure qualité)
- `text-embedding-3-small` d'OpenAI (si budget disponible)

---

## 9. Champ `yara_rule` — format et contenu

### Ce que contient ce champ

La règle YARA complète, prête à être utilisée comme exemple few-shot dans le prompt LLM.

### Format standard présent dans le dataset

```yara
rule NomDeLaRegle {
    meta:
        description = "Détecte le malware X"
        author = "Source"
        date = "2024-01-01"
        reference = "https://..."
    strings:
        $s1 = "string_malveillante" ascii wide nocase
        $s2 = { 4D 5A 90 00 hex_pattern }
        $s3 = /regex_pattern/
    condition:
        filesize < 2MB and
        any of ($s*)
}
```

### Points d'attention pour le LLM

- Certains records ont plusieurs règles YARA concaténées (signalé dans `notes_on_fp` : `"Record contains N YARA rules"`)
- Les règles synthétiques (S3, S4) ont une structure simplifiée mais syntaxiquement correcte
- Les `notes_on_fp` donnent des indications sur comment affiner la règle pour réduire les faux positifs

---

## 10. Niveaux de confiance — comment les utiliser

### Critères de scoring

| Critère | Points |
|---|---|
| Famille reconnue (dans liste de 150+ familles) | +2 |
| Famille présente mais non reconnue | +1 |
| Type identifié (pas unknown/generic) | +1 |
| Au moins 1 IOC | +1 |
| 3+ IOCs | +1 (bonus) |
| 2+ comportements | +1 |
| Règle YARA > 80 chars | +2 |
| Attack stage connu | +1 |
| 2+ strings/patterns | +1 |
| Description > 100 chars non bruitée | +1 |

| Score | Confiance |
|---|---|
| ≥ 7 | `high` |
| 3–6 | `medium` |
| < 3 | `low` (absent du dataset production) |

### Recommandation d'usage

```python
# Utiliser high + medium pour le retrieval général
production = [r for r in records if r['confidence'] in ('high', 'medium')]

# Utiliser high uniquement pour les exemples few-shot critiques
gold = [r for r in records if r['confidence'] == 'high']
```

---

## 11. Records synthétiques — comment les identifier

```python
import json

with open('dataset_production_enriched.json', 'r') as f:
    records = json.load(f)

# Séparer originaux et synthétiques
original  = [r for r in records if not r['id'].startswith('SYN-')]
synthetic = [r for r in records if r['id'].startswith('SYN-')]

print(f"Originaux    : {len(original)}")   # 2615
print(f"Synthétiques : {len(synthetic)}")  # 431

# Si vous ne voulez utiliser que les originaux
records_originaux_only = original
```

### Faut-il exclure les synthétiques ?

**Non, nous recommandons de les garder.** Les raisons :
- Les synthétiques ont 90.7% de famille connue vs 24% pour les originaux → meilleur retrieval par famille
- Ils couvrent des TTPs MITRE ATT&CK qui manquaient dans les originaux
- Les templates (S4) sont basés sur la documentation publique des familles et sont factuellement corrects
- Tous ont `confidence: medium` ou `high`, 0 embedding < 80 chars

Si vous souhaitez néanmoins les exclure pour un test A/B, utilisez le filtre `id.startswith('SYN-')`.

---

## 12. Limites connues et points d'attention

### Limite 1 — 66.6% des records ont `malware_family: unknown`

C'est **normal et attendu**. La majorité des fichiers YARA du dataset sont des règles génériques de détection de packers (`peid_*`), de techniques suspectes, ou de comportements non attribuables à une famille spécifique. Ces règles n'ont pas de famille par nature.

Pour le RAG, ce n'est pas un problème car le retrieval se fait sur `embedding_text` qui contient les comportements et types — pas uniquement sur la famille.

### Limite 2 — Descriptions variables en qualité

Les records de type `yara_cybersecurity_rule` (69% du dataset) ont des descriptions parfois courtes car construites depuis les noms de règles YARA. C'est pourquoi `embedding_text` est plus fiable que `description` pour le retrieval.

### Limite 3 — IOCs des livres pédagogiques

Les records issus de `practical_malware_analysis.pdf` contiennent des IOCs d'exercices (domaines d'outils d'analyse, IPs de test). Ces IOCs ont été filtrés au maximum mais certains peuvent subsister dans les records `TRJ-*` issus de ce livre.

### Limite 4 — Records multi-YARA

Quelques records contiennent plusieurs règles YARA concaténées. Identifiables via `notes_on_fp` qui contient `"Record contains N YARA rules"`. Recommandation : pour le few-shot LLM, extraire la première règle seulement via :

```python
import re
def get_first_yara_rule(yara_text):
    match = re.search(r'rule\s+\w+\s*\{.*?\}', yara_text, re.DOTALL)
    return match.group(0) if match else yara_text
```

### Limite 5 — Records synthétiques S4 avec descriptions identiques

Les variants WannaCry (SYN-RAN-043 à SYN-RAN-049) partagent la même description. Les règles YARA et les IOCs sont différents, mais les embeddings sont très proches. Impact RAG : mineur (redondance dans les résultats de retrieval pour WannaCry).

---

## 13. Exemples de records complets

### Exemple 1 — Record original high confidence (rootkit avec règle YARA)

```json
{
  "id": "RTK-001",
  "description": "RayInitiator is a persistent multi-stage bootkit facilitating deployment of LINE VIPER to Cisco ASA devices without secure boot.",
  "malware_family": "Hive",
  "malware_type": "rootkit",
  "behavior_summary": [
    "file encryption", "shellcode execution", "network communication",
    "anti-analysis", "data exfiltration", "bootkit/rootkit activity", "anti-forensics"
  ],
  "attack_stage": "defense-evasion",
  "ioc": ["ncsc.gov.uk", "nationalarchives.gov.uk"],
  "yara_rule": "rule RayInitiator_stage_1_search_for_booting_kernel_string { ... }",
  "rule_conditions": ["any of them"],
  "strings_or_patterns": ["sha512", "pkcs7", "intel-PC"],
  "source_document": "Malware Analysis Report - NCSC.pdf",
  "confidence": "high",
  "notes_on_fp": "Kernel-level hooks may match legitimate drivers | Record contains 8 YARA rules",
  "language": "en",
  "embedding_text": "rayinitiator persistent multi-stage bootkit facilitating deployment line viper hive hive rootkit rayinitiator stage search booting kernel string file encryption shellcode execution network communication anti-analysis defense-evasion sha512 pkcs7",
  "source_type": "malware_report"
}
```

---

### Exemple 2 — Record synthétique cross-famille (S2)

```json
{
  "id": "SYN-LDR-009",
  "description": "QuasarRAT acting as initial loader delivering BabbleLoader payload. QuasarRAT establishes persistence and lateral movement while BabbleLoader executes loader payload on target system.",
  "malware_family": "BabbleLoader",
  "malware_type": "loader",
  "behavior_summary": [
    "network communication", "persistence via scheduled task",
    "shellcode execution", "lateral movement", "data exfiltration"
  ],
  "attack_stage": "command-and-control",
  "ioc": ["quasarrat.exe", "babbleloader.dll"],
  "yara_rule": "rule QuasarRAT_detection_v1 { ... }",
  "rule_conditions": ["any of them"],
  "strings_or_patterns": ["QuasarRAT", "BabbleLoader"],
  "source_document": "synthetic_cross_family",
  "confidence": "medium",
  "notes_on_fp": "Synthetic cross-family scenario: QuasarRAT + BabbleLoader | synthetic:combination",
  "language": "en",
  "embedding_text": "quasarrat acting as initial loader delivering babbleloader payload babbleloader babbleloader loader network communication persistence via scheduled task shellcode execution lateral movement command-and-control quasarrat.exe babbleloader.dll",
  "source_type": "synthetic"
}
```

---

### Exemple 3 — Record MITRE ATT&CK (S3)

```json
{
  "id": "SYN-TRJ-189",
  "description": "Process hollowing technique injecting malicious code into legitimate explorer.exe process to evade detection.",
  "malware_family": "unknown",
  "malware_type": "trojan",
  "behavior_summary": [
    "process hollowing", "process injection", "shellcode execution", "anti-analysis"
  ],
  "attack_stage": "defense-evasion",
  "ioc": ["svchost.exe", "explorer.exe"],
  "yara_rule": "rule Process_hollowing_technique_injecting_malicious { ... }",
  "rule_conditions": ["any of them"],
  "strings_or_patterns": [
    "VirtualAllocEx", "WriteProcessMemory",
    "CreateRemoteThread", "NtUnmapViewOfSection"
  ],
  "source_document": "synthetic_mitre_attck",
  "confidence": "medium",
  "notes_on_fp": "Synthetic MITRE ATT&CK scenario: defense-evasion | synthetic:mitre",
  "language": "en",
  "embedding_text": "process hollowing technique injecting malicious code into legitimate explorer.exe process to evade detection trojan process hollowing process injection shellcode execution anti-analysis defense-evasion svchost.exe explorer.exe virtualallocex writeprocessmemory createremotethread ntunmapviewofsection",
  "source_type": "synthetic"
}
```

---

## 14. Fichiers livrés

### Fichier principal

```
data/processed/filtered/dataset_production_enriched.json
```
3 046 records — à utiliser pour la vectorisation et l'indexation RAG.

### Fichiers secondaires (pour référence)

```
data/processed/filtered/
├── dataset_production.json        → 2 615 records (avant enrichissement synthétique)
├── dataset_high_quality.json      → ~1 453 records confidence=high uniquement
├── dataset_all_filtered.json      → Tous les records valides incluant low
└── dataset_rejected.json          → 229 records écartés (pour audit)
```

### Scripts sources (branche feature/nlp)

```
src/
├── preprocessing/
│   ├── document_loader.py
│   ├── text_cleaner.py
│   ├── entity_extractor.py
│   ├── source_adapter.py
│   ├── schema_builder.py
│   ├── embedding_text_gen.py
│   └── knowledge_base.py
├── validation/
│   └── data_quality_filter.py
└── augmentation/
    └── synthetic_data_generator.py

run_preprocessing.py    → Lance le pipeline complet
```

### Pour relancer le pipeline complet

```bash
# 1. Pipeline NLP principal
python run_preprocessing.py

# 2. Filtrage qualité
python src/validation/data_quality_filter.py

# 3. Enrichissement synthétique
python src/augmentation/synthetic_data_generator.py
```

---

*Document produit par l'équipe NLP — branche `feature/nlp`*  
*Dataset livré : `dataset_production_enriched.json` — 3 046 records*



## Academic Context

Module: Natural Language Processing (NLP)

Project Topic: Automatic YARA Rule Generation using Retrieval-Augmented Generation (RAG)

Academic Year: 2025-2026