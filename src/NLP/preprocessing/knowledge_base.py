# src/preprocessing/knowledge_base.py

from pathlib import Path
from typing import List, Dict
import json

from .document_loader import load_all_documents
from .text_cleaner import TextCleaner
from .entity_extractor import EntityExtractor
from .source_adapter import SourceAdapter
from .schema_builder import SchemaBuilder
from .embedding_text_gen import generate_embedding_text, validate_embedding_text, get_embedding_stats


class KnowledgeBaseBuilder:
    def __init__(self, data_dir: Path, split_yara_records: bool = False):
        self.data_dir = data_dir
        self.split_yara_records = split_yara_records
        self.cleaner = TextCleaner()
        self.extractor = EntityExtractor()
        self.adapter = SourceAdapter(entity_extractor=self.extractor)
        self.builder = SchemaBuilder(self.extractor, self.adapter)

    def build(self) -> List[Dict]:
        print("=" * 60)
        print("🚀 CONSTRUCTION DE LA BASE DE CONNAISSANCES v4")
        print("=" * 60)

        print("\n📥 Étape 1/7 : Chargement des documents...")
        documents = load_all_documents(self.data_dir)
        print(f"   ✓ {len(documents)} documents chargés")

        print("\n🧹 Étape 2/7 : Nettoyage du texte...")
        for doc in documents:
            raw = doc.get('raw_text', '')
            doc['cleaned_text'] = self.cleaner.clean(raw)
            doc['extraction_text'] = self.cleaner.clean_for_extraction(raw)
            doc['natural_text'] = self.cleaner.extract_text_sentences_only(raw)
        print("   ✓ Nettoyage terminé")

        print("\n🔍 Étape 3-5/7 : Extraction d'entités et construction du schéma...")
        records = []
        errors = []
        for doc in documents:
            try:
                record = self.builder.build_record(doc)
                records.append(record)
            except Exception as e:
                errors.append(f"{doc['filename']}: {str(e)}")
                print(f"   ⚠️  Erreur sur {doc['filename']}: {e}")
        
        if errors:
            print(f"   ⚠️  {len(errors)} erreurs (voir détails ci-dessus)")
        print(f"   ✓ {len(records)} records construits")

        print("\n📝 Étape 6/7 : Génération des textes d'embedding...")
        valid_records = []
        skipped = 0
        skipped_details = []
        
        for record in records:
            record['embedding_text'] = generate_embedding_text(record)
            if validate_embedding_text(
                record['embedding_text'],
                source_type=record.get('source_type', '')
            ):
                valid_records.append(record)
            else:
                stats = get_embedding_stats(record)
                skipped_details.append({
                    'id': record['id'],
                    'source': record['source_document'],
                    'chars': stats['total_chars'],
                    'type': record.get('source_type', 'unknown')
                })
                skipped += 1

        if skipped > 0:
            print(f"   ⚠️  {skipped} records ignorés (embedding trop court):")
            for detail in skipped_details[:10]:  # Afficher les 10 premiers
                print(f"      - {detail['id']} ({detail['source']}): {detail['chars']} chars")
            if len(skipped_details) > 10:
                print(f"      ... et {len(skipped_details) - 10} autres")
        
        print(f"   ✓ {len(valid_records)} records valides, {skipped} ignorés")

        print("\n✅ Étape 7/7 : Validation finale...")
        self._validate_records(valid_records)

        return valid_records

    def _validate_records(self, records: List[Dict]):
        total = len(records)
        if total == 0:
            print("   ⚠️  Aucun record valide !")
            return

        # Stats globales
        stats = {
            'total': total,
            'with_family': sum(1 for r in records if r.get('malware_family') not in ('unknown', '')),
            'with_type': sum(1 for r in records if r.get('malware_type') not in ('unknown', '', 'generic', 'suspicious', 'documentation')),
            'with_ioc': sum(1 for r in records if r.get('ioc')),
            'with_yara': sum(1 for r in records if r.get('yara_rule')),
            'with_behaviors': sum(1 for r in records if r.get('behavior_summary')),
            'with_attack_stage': sum(1 for r in records if r.get('attack_stage') not in ('unknown', '')),
            'high_confidence': sum(1 for r in records if r.get('confidence') == 'high'),
            'medium_confidence': sum(1 for r in records if r.get('confidence') == 'medium'),
            'low_confidence': sum(1 for r in records if r.get('confidence') == 'low'),
        }

        # Stats par source_type
        by_source = {}
        for r in records:
            st = r.get('source_type', 'unknown')
            if st not in by_source:
                by_source[st] = {'count': 0, 'with_family': 0, 'with_type': 0, 'high_conf': 0}
            by_source[st]['count'] += 1
            if r.get('malware_family') not in ('unknown', ''):
                by_source[st]['with_family'] += 1
            if r.get('malware_type') not in ('unknown', '', 'generic', 'suspicious', 'documentation'):
                by_source[st]['with_type'] += 1
            if r.get('confidence') == 'high':
                by_source[st]['high_conf'] += 1

        print("\n📊 Statistiques globales:")
        for key, value in stats.items():
            pct = f" ({value/total*100:.1f}%)" if key != 'total' else ""
            print(f"   {key:25} : {value}{pct}")

        print("\n📊 Statistiques par source:")
        for source, data in sorted(by_source.items()):
            pct_family = data['with_family'] / data['count'] * 100 if data['count'] > 0 else 0
            pct_type = data['with_type'] / data['count'] * 100 if data['count'] > 0 else 0
            pct_high = data['high_conf'] / data['count'] * 100 if data['count'] > 0 else 0
            print(f"   {source:30} : {data['count']:3d} records | "
                  f"family: {pct_family:5.1f}% | type: {pct_type:5.1f}% | high: {pct_high:5.1f}%")

        # Alertes qualité — seuils adaptés
        alerts = []
        
        if stats['with_family'] / total < 0.20:
            alerts.append(f"moins de 20% des records ont une famille identifiée ({stats['with_family']/total*100:.1f}%)")
        
        if stats['with_type'] / total < 0.30:
            alerts.append(f"moins de 30% des records ont un type identifié ({stats['with_type']/total*100:.1f}%)")
        
        if stats['with_attack_stage'] / total < 0.20:
            alerts.append(f"moins de 20% des records ont un attack_stage ({stats['with_attack_stage']/total*100:.1f}%)")
        
        if stats['low_confidence'] / total > 0.50:
            alerts.append(f"plus de 50% des records ont une confiance 'low' ({stats['low_confidence']/total*100:.1f}%)")
        
        if stats['with_yara'] > 0 and stats['with_yara'] == stats['with_family']:
            # Si tous les YARA ont une famille, c'est suspect (faux positifs)
            pass  # Normal si les règles ont des noms explicites

        if alerts:
            print("\n   ⚠️  ALERTES QUALITÉ:")
            for alert in alerts:
                print(f"       → {alert}")
            print("\n       Recommandations:")
            print("       - Vérifier que source_adapter passe bien yara_text aux extracteurs")
            print("       - Vérifier les mappings de famille dans _extract_family_from_yara()")
            print("       - Augmenter la couverture des patterns de type dans _infer_type_from_yara()")
        else:
            print("\n   ✅ Qualité globale satisfaisante")

    def save(self, records: List[Dict], output_path: Path):
        output_path.parent.mkdir(parents=True, exist_ok=True)

        export_records = []
        for r in records:
            export_r = {k: v for k, v in r.items()
                       if k not in ('extraction_text', 'natural_text', 'yara_rules_count')}
            export_records.append(export_r)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_records, f, indent=2, ensure_ascii=False)

        size_kb = output_path.stat().st_size / 1024
        print(f"\n💾 Base de connaissances sauvegardée : {output_path}")
        print(f"   Taille : {size_kb:.1f} Ko | {len(export_records)} records")

    def save_debug(self, records: List[Dict], output_path: Path):
        output_path.parent.mkdir(parents=True, exist_ok=True)

        debug_records = []
        for r in records:
            debug_r = dict(r)
            debug_r['_embedding_stats'] = get_embedding_stats(r)
            debug_records.append(debug_r)

        debug_path = output_path.with_stem(output_path.stem + '_debug')
        with open(debug_path, 'w', encoding='utf-8') as f:
            json.dump(debug_records, f, indent=2, ensure_ascii=False)

        print(f"   🔍 Fichier debug : {debug_path}")


def main():
    data_dir = Path("data/raw")
    output_path = Path("data/knowledge_base.json")
    builder = KnowledgeBaseBuilder(data_dir)
    records = builder.build()
    builder.save(records, output_path)


if __name__ == "__main__":
    main()