#!/usr/bin/env python3
"""
================================================================================
SCRIPT DE TEST COMPLET - Module Preprocessing NLP
YARA-RAG-Generator
================================================================================

Ce script teste automatiquement tout le pipeline de preprocessing :
1. Chargement des documents
2. Nettoyage du texte
3. Extraction d'entités
4. Adaptation par source
5. Construction du schéma
6. Génération de l'embedding_text
7. Pipeline complet (KnowledgeBaseBuilder)

Usage:
    python test_preprocessing_complete.py

Auteur: Auto-généré pour le projet YARA-RAG
Date: 2026-06-07
"""

import sys
import json
import re
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any

# =============================================================================
# CONFIGURATION
# =============================================================================

PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
TEST_OUTPUT_DIR = PROJECT_ROOT / "test_outputs"

# Couleurs pour le terminal (Windows compatible)
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def print_header(title: str):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}  {title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")

def print_success(msg: str):
    print(f"{Colors.GREEN}✅ {msg}{Colors.RESET}")

def print_error(msg: str):
    print(f"{Colors.RED}❌ {msg}{Colors.RESET}")

def print_warning(msg: str):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.RESET}")

def print_info(msg: str):
    print(f"{Colors.BLUE}ℹ️  {msg}{Colors.RESET}")

# =============================================================================
# STATISTIQUES GLOBALES
# =============================================================================

class TestStats:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.tests = []

    def add_pass(self, name: str, details: str = ""):
        self.passed += 1
        self.tests.append(("PASS", name, details))
        print_success(f"{name} {details}")

    def add_fail(self, name: str, details: str = ""):
        self.failed += 1
        self.tests.append(("FAIL", name, details))
        print_error(f"{name} {details}")

    def add_warning(self, name: str, details: str = ""):
        self.warnings += 1
        self.tests.append(("WARN", name, details))
        print_warning(f"{name} {details}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 RÉSUMÉ DES TESTS{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"  Total tests  : {total}")
        print(f"  {Colors.GREEN}Réussis      : {self.passed}{Colors.RESET}")
        print(f"  {Colors.RED}Échoués      : {self.failed}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Avertissements : {self.warnings}{Colors.RESET}")

        if self.failed == 0:
            print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 TOUS LES TESTS ONT RÉUSSI !{Colors.RESET}")
        else:
            rate = (self.passed / total) * 100 if total > 0 else 0
            print(f"\n{Colors.YELLOW}Taux de réussite : {rate:.1f}%{Colors.RESET}")

        return self.failed == 0

stats = TestStats()

# =============================================================================
# TEST 1 : VÉRIFICATION DE LA STRUCTURE DU PROJET
# =============================================================================

print_header("TEST 1 : Vérification de la structure du projet")

required_files = [
    "src/preprocessing/__init__.py",
    "src/preprocessing/config.py",
    "src/preprocessing/document_loader.py",
    "src/preprocessing/text_cleaner.py",
    "src/preprocessing/entity_extractor.py",
    "src/preprocessing/source_adapter.py",
    "src/preprocessing/schema_builder.py",
    "src/preprocessing/embedding_text_gen.py",
    "src/preprocessing/knowledge_base.py",
    "src/preprocessing/utils.py",
]

missing_files = []
for file in required_files:
    path = PROJECT_ROOT / file
    if path.exists():
        stats.add_pass(f"Fichier existe", f"{file}")
    else:
        stats.add_fail(f"Fichier manquant", f"{file}")
        missing_files.append(file)

if missing_files:
    print_error(f"\n{len(missing_files)} fichier(s) manquant(s) !")
    for f in missing_files:
        print(f"   - {f}")

# =============================================================================
# TEST 2 : VÉRIFICATION DES DONNÉES BRUTES
# =============================================================================

print_header("TEST 2 : Vérification des données brutes (data/raw/)")

if not RAW_DATA_DIR.exists():
    stats.add_fail("Dossier data/raw/", "N'existe pas ! Créez-le et copiez les données du Drive.")
    print_error("\n❌ ERREUR CRITIQUE : Le dossier data/raw/ n'existe pas.")
    print_info("Solution : Créez data/raw/ et copiez-y les dossiers du Google Drive.")
    sys.exit(1)

# Compter les fichiers par type
file_counts = Counter()
folder_counts = Counter()
total_files = 0

for file_path in RAW_DATA_DIR.rglob('*'):
    if file_path.is_file():
        total_files += 1
        ext = file_path.suffix.lower()
        file_counts[ext] += 1
        folder_counts[file_path.parent.name] += 1

print_info(f"Total fichiers trouvés : {total_files}")
print_info(f"Dossiers trouvés : {len(folder_counts)}")

if total_files == 0:
    stats.add_fail("Fichiers dans data/raw/", "Aucun fichier trouvé !")
    print_error("\n❌ ERREUR : data/raw/ est vide.")
    sys.exit(1)
else:
    stats.add_pass("Fichiers présents", f"{total_files} fichiers dans {len(folder_counts)} dossiers")

# Afficher la répartition
print(f"\n{Colors.BOLD}Répartition par type de fichier :{Colors.RESET}")
for ext, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"   {ext or '(sans extension)':12} : {count:3d} fichiers")

print(f"\n{Colors.BOLD}Répartition par dossier :{Colors.RESET}")
for folder, count in sorted(folder_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"   {folder:30} : {count:3d} fichiers")

# =============================================================================
# TEST 3 : TEST DES IMPORTS
# =============================================================================

print_header("TEST 3 : Vérification des imports des modules")

modules_to_test = [
    ("src.preprocessing.config", "config"),
    ("src.preprocessing.utils", "utils"),
    ("src.preprocessing.text_cleaner", "TextCleaner"),
    ("src.preprocessing.entity_extractor", "EntityExtractor"),
    ("src.preprocessing.source_adapter", "SourceAdapter"),
    ("src.preprocessing.schema_builder", "SchemaBuilder"),
    ("src.preprocessing.embedding_text_gen", "generate_embedding_text"),
    ("src.preprocessing.document_loader", "load_all_documents"),
    ("src.preprocessing.knowledge_base", "KnowledgeBaseBuilder"),
]

for module_name, attr_name in modules_to_test:
    try:
        module = __import__(module_name, fromlist=[attr_name])
        getattr(module, attr_name)
        stats.add_pass(f"Import", f"{module_name}.{attr_name}")
    except ImportError as e:
        stats.add_fail(f"Import", f"{module_name} - {e}")
    except AttributeError as e:
        stats.add_fail(f"Import", f"{module_name}.{attr_name} non trouvé - {e}")

# =============================================================================
# TEST 4 : TEST DU TEXT CLEANER
# =============================================================================

print_header("TEST 4 : Test du TextCleaner")

try:
    from src.preprocessing.text_cleaner import TextCleaner
    cleaner = TextCleaner()

    # Test 1 : Nettoyage basique
    text1 = "  Bonjour   monde  !  Page 1 of 10  © 2024 All rights reserved  "
    result1 = cleaner.clean(text1)
    assert "Page 1 of 10" not in result1, "Page number non supprimée"
    assert "© 2024" not in result1, "Copyright non supprimé"
    assert "  " not in result1, "Espaces multiples non normalisés"
    stats.add_pass("TextCleaner", "Nettoyage basique OK")

    # Test 2 : Nettoyage règle YARA
    yara_rule = """
    rule test {
        // commentaire inline
        /* commentaire
           multiligne */
        strings:
            $a = "test"
        condition:
            any of them
    }
    """
    result2 = cleaner.clean_yara_rule(yara_rule)
    assert "// commentaire" not in result2, "Commentaire inline non supprimé"
    assert "/* commentaire" not in result2, "Commentaire multiligne non supprimé"
    assert "$a = \"test\"" in result2, "Strings supprimées par erreur"
    stats.add_pass("TextCleaner", "Nettoyage YARA OK")

    # Test 3 : Texte vide
    result3 = cleaner.clean("")
    assert result3 == "", "Texte vide mal géré"
    stats.add_pass("TextCleaner", "Gestion texte vide OK")

except Exception as e:
    stats.add_fail("TextCleaner", f"Exception : {e}")

# =============================================================================
# TEST 5 : TEST DE L'ENTITY EXTRACTOR
# =============================================================================

print_header("TEST 5 : Test de l'EntityExtractor")

try:
    from src.preprocessing.entity_extractor import EntityExtractor
    extractor = EntityExtractor()

    # Test 1 : Extraction famille malware
    text1 = "The LockBit ransomware encrypts files using AES-256"
    family = extractor.extract_malware_family(text1)
    assert family == "LockBit", f"Famille incorrecte : {family}"
    stats.add_pass("EntityExtractor", "Extraction famille LockBit OK")

    # Test 2 : Extraction type malware
    type_mw = extractor.extract_malware_type(text1)
    assert type_mw == "ransomware", f"Type incorrect : {type_mw}"
    stats.add_pass("EntityExtractor", "Extraction type ransomware OK")

    # Test 3 : Extraction IOCs
    text2 = "Contact 192.168.1.1 or evil.com, hash: d41d8cd98f00b204e9800998ecf8427e"
    iocs = extractor.extract_iocs(text2)
    assert any("192.168.1.1" in ioc for ioc in iocs), "IP non extraite"
    assert any("evil.com" in ioc for ioc in iocs), "Domaine non extrait"
    assert any("d41d8cd98f00b204e9800998ecf8427e" in ioc for ioc in iocs), "Hash MD5 non extrait"
    stats.add_pass("EntityExtractor", f"Extraction IOCs OK ({len(iocs)} trouvés)")

    # Test 4 : Extraction comportements
    behaviors = extractor.extract_behaviors(text1)
    assert any("encrypt" in b.lower() for b in behaviors), "Comportement encryption non détecté"
    stats.add_pass("EntityExtractor", f"Extraction comportements OK ({len(behaviors)} trouvés)")

    # Test 5 : Extraction stage d'attaque
    stage = extractor.extract_attack_stage(text1)
    assert stage != "unknown", "Stage non détecté"
    stats.add_pass("EntityExtractor", f"Extraction stage OK ({stage})")

    # Test 6 : Extraction règle YARA
    text3 = """
    Some text before
    rule LockBit_AES {
        strings:
            $a = "AES" wide
            $b = { 25 50 44 46 }
        condition:
            uint16(0) == 0x5A4D and all of them
    }
    Some text after
    """
    yara_rule = extractor.extract_yara_rule(text3)
    assert yara_rule is not None, "Règle YARA non extraite"
    assert "rule LockBit_AES" in yara_rule, "Nom de règle incorrect"
    stats.add_pass("EntityExtractor", "Extraction règle YARA OK")

    # Test 7 : Extraction conditions de règle
    conditions = extractor.extract_rule_conditions(yara_rule)
    assert "uint16" in conditions or "filesize" in conditions or any("uint" in c for c in conditions), "Conditions non extraites"
    stats.add_pass("EntityExtractor", f"Extraction conditions OK ({len(conditions)} trouvées)")

    # Test 8 : Extraction strings de règle
    strings = extractor.extract_strings_patterns(yara_rule)
    assert any("AES" in s for s in strings), "String AES non extraite"
    stats.add_pass("EntityExtractor", f"Extraction strings OK ({len(strings)} trouvées)")

except Exception as e:
    stats.add_fail("EntityExtractor", f"Exception : {e}")
    import traceback
    traceback.print_exc()

# =============================================================================
# TEST 6 : TEST DU SOURCE ADAPTER
# =============================================================================

print_header("TEST 6 : Test du SourceAdapter")

try:
    from src.preprocessing.entity_extractor import EntityExtractor
    from src.preprocessing.source_adapter import SourceAdapter

    extractor = EntityExtractor()
    adapter = SourceAdapter(extractor)

    # Test 1 : Rapport malware
    doc1 = {
        'source_folder': 'Rapports malware',
        'filename': 'report_lockbit.pdf',
        'raw_text': 'LockBit ransomware encrypts files using AES-256. Deletes shadow copies via vssadmin.',
        'doc_type': 'pdf'
    }
    result1 = adapter.adapt(doc1)
    assert result1['source_type'] == 'malware_report', f"Type incorrect : {result1['source_type']}"
    assert result1['malware_family'] == 'LockBit', f"Famille incorrecte : {result1['malware_family']}"
    stats.add_pass("SourceAdapter", "Adaptation Rapport Malware OK")

    # Test 2 : Règle YARA
    doc2 = {
        'source_folder': 'rules-yara-cybersecurity',
        'filename': 'lockbit.yar',
        'raw_text': 'rule LockBit { strings: $a = "AES" condition: any of them }',
        'doc_type': 'yara'
    }
    result2 = adapter.adapt(doc2)
    assert result2['source_type'] == 'yara_cybersecurity_rule', f"Type incorrect : {result2['source_type']}"
    assert result2['yara_rule'] != "", "Règle YARA non extraite"
    stats.add_pass("SourceAdapter", "Adaptation Règle YARA OK")

    # Test 3 : Données structurées (JSON)
    doc3 = {
        'source_folder': 'YARA csv-json',
        'filename': 'data.json',
        'raw_text': '{"malware_family": "Emotet", "malware_type": "trojan"}',
        'doc_type': 'json',
        'structured_data': {
            'malware_family': 'Emotet',
            'malware_type': 'trojan',
            'description': 'Banking trojan'
        }
    }
    result3 = adapter.adapt(doc3)
    assert result3['source_type'] == 'structured_data', f"Type incorrect : {result3['source_type']}"
    assert result3['malware_family'] == 'Emotet', f"Famille incorrecte : {result3['malware_family']}"
    stats.add_pass("SourceAdapter", "Adaptation Données Structurées OK")

    # Test 4 : Documentation YARA
    doc4 = {
        'source_folder': 'YARA Documentations',
        'filename': 'writing_rules.html',
        'raw_text': '<h1>Writing YARA Rules</h1><p>Documentation...</p><pre>rule example { condition: true }</pre>',
        'doc_type': 'html'
    }
    result4 = adapter.adapt(doc4)
    assert result4['source_type'] == 'yara_documentation', f"Type incorrect : {result4['source_type']}"
    stats.add_pass("SourceAdapter", "Adaptation Documentation YARA OK")

    # Test 5 : Threat Intelligence
    doc5 = {
        'source_folder': 'Threat intelligence et IOC',
        'filename': 'ioc_list.txt',
        'raw_text': 'IPs: 192.168.1.1, 10.0.0.1. Domains: evil.com, bad.net',
        'doc_type': 'txt'
    }
    result5 = adapter.adapt(doc5)
    assert result5['source_type'] == 'threat_intelligence', f"Type incorrect : {result5['source_type']}"
    assert len(result5['ioc']) > 0, "IOCs non extraits"
    stats.add_pass("SourceAdapter", "Adaptation Threat Intelligence OK")

except Exception as e:
    stats.add_fail("SourceAdapter", f"Exception : {e}")
    import traceback
    traceback.print_exc()

# =============================================================================
# TEST 7 : TEST DU SCHEMA BUILDER
# =============================================================================

print_header("TEST 7 : Test du SchemaBuilder")

try:
    from src.preprocessing.entity_extractor import EntityExtractor
    from src.preprocessing.source_adapter import SourceAdapter
    from src.preprocessing.schema_builder import SchemaBuilder

    extractor = EntityExtractor()
    adapter = SourceAdapter(extractor)
    builder = SchemaBuilder(extractor, adapter)

    # Test 1 : Construction record complet
    doc = {
        'source_folder': 'Rapports malware',
        'filename': 'test_report.pdf',
        'raw_text': 'LockBit ransomware encrypts files using AES-256 and deletes shadow copies. IOC: .locked extension',
        'doc_type': 'pdf'
    }

    record = builder.build_record(doc)

    # Vérifier champs obligatoires
    required_fields = [
        'id', 'description', 'malware_family', 'malware_type',
        'behavior_summary', 'attack_stage', 'ioc', 'yara_rule',
        'rule_conditions', 'strings_or_patterns', 'source_document',
        'confidence', 'notes_on_fp', 'language', 'embedding_text'
    ]

    for field in required_fields:
        assert field in record, f"Champ '{field}' manquant"
    stats.add_pass("SchemaBuilder", "Tous les champs obligatoires présents")

    # Vérifier valeurs
    assert record['malware_family'] == 'LockBit', f"Famille : {record['malware_family']}"
    assert record['malware_type'] == 'ransomware', f"Type : {record['malware_type']}"
    assert len(record['ioc']) > 0, "Pas d'IOCs"
    assert len(record['behavior_summary']) > 0, "Pas de comportements"
    assert record['embedding_text'] != "", "embedding_text vide"
    assert record['id'].startswith('REC-'), f"ID mal formaté : {record['id']}"
    stats.add_pass("SchemaBuilder", "Valeurs du record correctes")

    # Test 2 : Record avec règle YARA
    doc2 = {
        'source_folder': 'rules',
        'filename': 'test.yar',
        'raw_text': 'rule TestRule { strings: $a = "test" condition: any of them }',
        'doc_type': 'yara'
    }
    record2 = builder.build_record(doc2)
    assert record2['yara_rule'] != "", "Règle YARA non préservée"
    assert record2['source_type'] == 'yara_rule', f"Type : {record2['source_type']}"
    stats.add_pass("SchemaBuilder", "Record avec règle YARA OK")

    # Test 3 : Confiance
    assert record['confidence'] in ['high', 'medium', 'low'], f"Confiance invalide : {record['confidence']}"
    stats.add_pass("SchemaBuilder", f"Niveau de confiance : {record['confidence']}")

    # Test 4 : Language
    assert record['language'] in ['en', 'fr', 'unknown'], f"Langue invalide : {record['language']}"
    stats.add_pass("SchemaBuilder", f"Langue détectée : {record['language']}")

except Exception as e:
    stats.add_fail("SchemaBuilder", f"Exception : {e}")
    import traceback
    traceback.print_exc()

# =============================================================================
# TEST 8 : TEST DE L'EMBEDDING TEXT GENERATOR
# =============================================================================

print_header("TEST 8 : Test de l'Embedding Text Generator")

try:
    from src.preprocessing.embedding_text_gen import generate_embedding_text, validate_embedding_text

    # Test 1 : Génération basique
    record = {
        'description': 'Ransomware encrypts files',
        'malware_family': 'LockBit',
        'malware_type': 'ransomware',
        'behavior_summary': ['file encryption', 'AES usage'],
        'attack_stage': 'impact',
        'ioc': ['.locked', 'ransom_note.txt'],
        'strings_or_patterns': ['AES', 'encrypt']
    }

    embedding = generate_embedding_text(record)
    assert 'lockbit' in embedding.lower(), "Famille non dans embedding"
    assert 'ransomware' in embedding.lower(), "Type non dans embedding"
    assert 'encrypt' in embedding.lower(), "Description non dans embedding"
    assert len(embedding) > 50, "Embedding trop court"
    stats.add_pass("EmbeddingText", f"Génération OK ({len(embedding)} caractères)")

    # Test 2 : Validation
    assert validate_embedding_text(embedding), "Validation échouée"
    stats.add_pass("EmbeddingText", "Validation OK")

    # Test 3 : Texte trop court
    short_text = "short"
    assert not validate_embedding_text(short_text, min_length=100), "Validation aurait dû échouer"
    stats.add_pass("EmbeddingText", "Rejet texte trop court OK")

    # Test 4 : Record vide
    empty_record = {}
    empty_embedding = generate_embedding_text(empty_record)
    assert empty_embedding == "", "Embedding non vide pour record vide"
    stats.add_pass("EmbeddingText", "Gestion record vide OK")

except Exception as e:
    stats.add_fail("EmbeddingText", f"Exception : {e}")
    import traceback
    traceback.print_exc()

# =============================================================================
# TEST 9 : TEST DU DOCUMENT LOADER (si données disponibles)
# =============================================================================

print_header("TEST 9 : Test du DocumentLoader")

try:
    from src.preprocessing.document_loader import load_all_documents

    if RAW_DATA_DIR.exists() and any(RAW_DATA_DIR.iterdir()):
        documents = load_all_documents(RAW_DATA_DIR)

        if len(documents) > 0:
            stats.add_pass("DocumentLoader", f"{len(documents)} documents chargés")

            # Vérifier structure
            required_doc_fields = ['source_folder', 'filename', 'file_path', 'doc_type', 'raw_text']
            for field in required_doc_fields:
                assert field in documents[0], f"Champ '{field}' manquant dans document"
            stats.add_pass("DocumentLoader", "Structure des documents correcte")

            # Répartition par type
            doc_types = Counter([d['doc_type'] for d in documents])
            print(f"\n{Colors.BOLD}Types de documents :{Colors.RESET}")
            for dtype, count in doc_types.most_common():
                print(f"   {dtype:10} : {count:3d}")

            # Répartition par dossier source
            folders = Counter([d['source_folder'] for d in documents])
            print(f"\n{Colors.BOLD}Dossiers sources :{Colors.RESET}")
            for folder, count in folders.most_common():
                print(f"   {folder:30} : {count:3d}")

        else:
            stats.add_warning("DocumentLoader", "Aucun document chargé (vérifiez les extensions)")
    else:
        stats.add_warning("DocumentLoader", "Données brutes non disponibles - test ignoré")

except Exception as e:
    stats.add_fail("DocumentLoader", f"Exception : {e}")
    import traceback
    traceback.print_exc()

# =============================================================================
# TEST 10 : TEST DU PIPELINE COMPLET (si données disponibles)
# =============================================================================

print_header("TEST 10 : Test du Pipeline Complet (KnowledgeBaseBuilder)")

try:
    from src.preprocessing.knowledge_base import KnowledgeBaseBuilder

    if RAW_DATA_DIR.exists() and any(RAW_DATA_DIR.iterdir()):
        # Créer le dossier de sortie
        TEST_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_file = TEST_OUTPUT_DIR / "knowledge_base_test.json"

        builder = KnowledgeBaseBuilder(RAW_DATA_DIR)
        records = builder.build()

        if len(records) > 0:
            builder.save(records, output_file)
            stats.add_pass("KnowledgeBaseBuilder", f"{len(records)} records générés")

            # Vérifier le fichier de sortie
            assert output_file.exists(), "Fichier de sortie non créé"
            stats.add_pass("KnowledgeBaseBuilder", f"Fichier sauvegardé : {output_file}")

            # Charger et vérifier
            with open(output_file, 'r', encoding='utf-8') as f:
                saved_records = json.load(f)

            assert len(saved_records) == len(records), "Nombre de records incohérent"
            stats.add_pass("KnowledgeBaseBuilder", "Fichier JSON valide")

            # Statistiques
            print(f"\n{Colors.BOLD}Statistiques des records :{Colors.RESET}")

            confidences = Counter([r['confidence'] for r in records])
            print(f"   Confiance : {dict(confidences)}")

            families = Counter([r['malware_family'] for r in records])
            print(f"   Familles (top 5) : {dict(families.most_common(5))}")

            types = Counter([r['malware_type'] for r in records])
            print(f"   Types : {dict(types)}")

            stages = Counter([r['attack_stage'] for r in records])
            print(f"   Stages : {dict(stages)}")

            source_types = Counter([r['source_type'] for r in records])
            print(f"   Types de source : {dict(source_types)}")

            # Afficher un exemple
            print(f"\n{Colors.BOLD}Exemple de record :{Colors.RESET}")
            print(json.dumps(records[0], indent=2, ensure_ascii=False)[:1000])
            print("...")

            # Validation du schéma
            print(f"\n{Colors.BOLD}Validation du schéma :{Colors.RESET}")
            schema_errors = []
            required_fields = [
                'id', 'description', 'malware_family', 'malware_type',
                'behavior_summary', 'attack_stage', 'ioc', 'yara_rule',
                'rule_conditions', 'strings_or_patterns', 'source_document',
                'confidence', 'notes_on_fp', 'language', 'embedding_text'
            ]

            for i, record in enumerate(records):
                for field in required_fields:
                    if field not in record:
                        schema_errors.append(f"Record {i} ({record.get('id', '?')}): champ '{field}' manquant")

                if not record.get('embedding_text'):
                    schema_errors.append(f"Record {i} ({record.get('id', '?')}): embedding_text vide")

            if schema_errors:
                print_warning(f"{len(schema_errors)} problèmes de schéma")
                for err in schema_errors[:5]:
                    print(f"   - {err}")
            else:
                stats.add_pass("KnowledgeBaseBuilder", "Schéma valide pour tous les records")

        else:
            stats.add_warning("KnowledgeBaseBuilder", "Aucun record généré")
    else:
        stats.add_warning("KnowledgeBaseBuilder", "Données brutes non disponibles - test ignoré")

except Exception as e:
    stats.add_fail("KnowledgeBaseBuilder", f"Exception : {e}")
    import traceback
    traceback.print_exc()

# =============================================================================
# RÉSUMÉ FINAL
# =============================================================================

print_header("RÉSULTATS FINAUX")

success = stats.summary()

# Sauvegarder le rapport
report_file = TEST_OUTPUT_DIR / "test_report.json"
TEST_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

report = {
    "date": str(Path(__file__).stat().st_mtime),
    "total_tests": stats.passed + stats.failed,
    "passed": stats.passed,
    "failed": stats.failed,
    "warnings": stats.warnings,
    "success_rate": (stats.passed / (stats.passed + stats.failed) * 100) if (stats.passed + stats.failed) > 0 else 0,
    "details": [
        {"status": status, "name": name, "details": details}
        for status, name, details in stats.tests
    ]
}

with open(report_file, 'w', encoding='utf-8') as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print(f"\n{Colors.BLUE}📄 Rapport sauvegardé : {report_file}{Colors.RESET}")

# Code de retour
sys.exit(0 if success else 1)