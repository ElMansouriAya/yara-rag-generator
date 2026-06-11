#  Dashboard Integration Guide

**Pour l'équipe Dashboard** — tout ce dont vous avez besoin est ici.

---

## 1. Installation

```bash
pip install -r requirements.txt
```

---

## 2. Import unique

```python
from api import YARARAGAPI
```

C'est le **seul import** dont vous avez besoin.

---

## 3. Initialisation

```python
# Qwen (recommandé — rapide)
api = YARARAGAPI(model="qwen")

# Flan-T5 (léger)
api = YARARAGAPI(model="flan")

# Mistral 7B (meilleure qualité, nécessite plus de VRAM)
api = YARARAGAPI(model="mistral")
```

---

## 4. Générer une règle YARA

```python
result = api.generate(
    query = "Ransomware encrypting files with AES and deleting shadow copies",
    mode  = "agentic"   # recommandé
)

# Ce que vous recevez :
print(result["yara_rule"])      # la règle YARA générée
print(result["valid"])          # True/False
print(result["syntax_score"])   # 0.0 à 1.0
print(result["sources"])        # documents utilisés pour générer
print(result["retriever_used"]) # quel retriever a été utilisé
print(result["iterations"])     # nombre d'itérations (agentic)
print(result["model"])          # modèle utilisé
```

**Modes disponibles :**

| Mode | Description | Recommandé pour |
|---|---|---|
| `"agentic"` | Loop validation + retry | Production |
| `"hybrid"` | FAISS + BM25 fusion | Tests |
| `"classic"` | Dense retrieval seul | Comparaison |
| `"baseline"` | Sans RAG | Démonstration |

---

## 5. Expliquer une règle

```python
explanation = api.explain(result["yara_rule"])
print(explanation)
# → "This rule detects ransomware behavior by looking for AES encryption
#    combined with shadow copy deletion via vssadmin..."
```

---

## 6. Rechercher dans la base de connaissances

```python
# Sans générer de règle — juste pour afficher des exemples similaires
docs = api.search("Ransomware with AES encryption", k=5)

for doc in docs:
    print(doc["id"])             # RAN-001
    print(doc["description"])    # description courte
    print(doc["malware_type"])   # ransomware
    print(doc["malware_family"]) # LockBit
    print(doc["score"])          # 0.95
    print(doc["confidence"])     # high
    print(doc["yara_rule"])      # règle YARA de référence
```

---

## 7. Statistiques du dataset

```python
stats = api.dataset_stats()

print(stats["total"])           # 3046
print(stats["by_type"])         # {"trojan": 1390, "ransomware": 209, ...}
print(stats["top_families"])    # {"LockBit": 12, "Emotet": 11, ...}
print(stats["by_confidence"])   # {"high": 1453, "medium": 1593}
```

---

## 8. Changer de modèle à la volée

```python
api.use_model("mistral")   # switch sans recharger la KB
result = api.generate(query, mode="agentic")
```

---

## 9. Benchmark 

```python
queries = [
    "Ransomware encrypting files with AES",
    "Worm spreading via SMB",
    "Keylogger with FTP exfiltration",
]
references = [
    "rule AES_Ransomware { ... }",
    "rule SMB_Worm { ... }",
    "rule Keylogger { ... }",
]

report = api.benchmark(queries, references)

# Tableau de métriques par mode
for mode, metrics in report["summary"].items():
    print(f"{mode}: BLEU={metrics['bleu']} Syntax={metrics['syntax_score']}")
```

---