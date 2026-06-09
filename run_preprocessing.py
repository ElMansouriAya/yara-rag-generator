#!/usr/bin/env python3
"""
==================================================
PIPELINE NLP v2 — YARA RAG Generator
==================================================
"""

import sys
import json
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent / "src"))

from preprocessing.knowledge_base import KnowledgeBaseBuilder


def print_quality_report(records):
    """Affiche un rapport qualité détaillé."""
    if not records:
        print("❌ Aucun record à analyser")
        return

    total = len(records)
    print(f"\n{'='*60}")
    print("📊 RAPPORT QUALITÉ DÉTAILLÉ")
    print(f"{'='*60}")

    # Par type de source
    print(f"\n📁 Par type de source :")
    types = Counter(r.get('source_type', 'unknown') for r in records)
    for stype, count in types.most_common():
        print(f"  {stype:35} : {count:3d} ({count/total*100:.0f}%)")

    # Par type de malware
    print(f"\n🦠 Par type de malware :")
    mtypes = Counter(r.get('malware_type', 'unknown') for r in records)
    for mtype, count in mtypes.most_common():
        print(f"  {mtype:20} : {count:3d} ({count/total*100:.0f}%)")

    # Par famille
    print(f"\n👨‍👩‍👧 Familles identifiées :")
    families = Counter(
        r.get('malware_family', 'unknown') for r in records
        if r.get('malware_family', 'unknown') not in ('unknown', 'yara_documentation')
    )
    for family, count in families.most_common(10):
        print(f"  {family:25} : {count:3d}")
    unknown_fam = sum(1 for r in records if r.get('malware_family', 'unknown') == 'unknown')
    if unknown_fam:
        print(f"  {'(unknown)':25} : {unknown_fam:3d}")

    # Confiance
    print(f"\n🎯 Niveaux de confiance :")
    conf = Counter(r.get('confidence', 'unknown') for r in records)
    for c, count in conf.most_common():
        print(f"  {c:10} : {count:3d} ({count/total*100:.0f}%)")

    # IOCs
    records_with_ioc = [r for r in records if r.get('ioc')]
    avg_iocs = sum(len(r['ioc']) for r in records_with_ioc) / max(len(records_with_ioc), 1)
    print(f"\n🔍 IOCs :")
    print(f"  Records avec IOCs    : {len(records_with_ioc):3d} ({len(records_with_ioc)/total*100:.0f}%)")
    print(f"  Moyenne IOCs/record  : {avg_iocs:.1f}")

    # YARA
    records_with_yara = [r for r in records if r.get('yara_rule')]
    print(f"\n📋 Règles YARA :")
    print(f"  Records avec règle   : {len(records_with_yara):3d} ({len(records_with_yara)/total*100:.0f}%)")

    # Embedding quality
    short_emb = [r for r in records if len(r.get('embedding_text', '')) < 100]
    print(f"\n📝 Embedding quality :")
    print(f"  Embeddings < 100 chars : {len(short_emb):3d}")
    avg_emb = sum(len(r.get('embedding_text', '')) for r in records) / total
    print(f"  Longueur moyenne       : {avg_emb:.0f} chars")


def main():
    data_dir = Path("data/raw")
    output_dir = Path("data/processed")
    output_file = output_dir / "knowledge_base.json"

    if not data_dir.exists():
        print("❌ ERREUR : data/raw/ n'existe pas !")
        print("   Copiez les dossiers du Drive dans data/raw/")
        sys.exit(1)

    if not any(data_dir.iterdir()):
        print("❌ ERREUR : data/raw/ est vide !")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("🚀 PIPELINE NLP v2 — YARA RAG Generator")
    print("=" * 60)
    print(f"📁 Sources : {data_dir.absolute()}")
    print(f"📤 Sortie  : {output_file.absolute()}")
    print("=" * 60)

    builder = KnowledgeBaseBuilder(data_dir)
    records = builder.build()

    # Sauvegarde principale
    builder.save(records, output_file)

    # Sauvegarde debug (optionnel)
    builder.save_debug(records, output_file)

    # Rapport qualité
    print_quality_report(records)

    print(f"\n{'='*60}")
    print(f"✅ Pipeline terminé : {len(records)} records")
    print(f"   Fichier JSON     : {output_file}")
    print(f"   → Transmettre à l'équipe RAG !")
    print(f"{'='*60}")

    return records


if __name__ == "__main__":
    main()