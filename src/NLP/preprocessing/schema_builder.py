# src/preprocessing/schema_builder.py


import re
from typing import Dict, List
from langdetect import detect


class SchemaBuilder:
    def __init__(self, entity_extractor, source_adapter):
        self.extractor = entity_extractor
        self.adapter = source_adapter
        self.counters: Dict[str, int] = {}

    def _make_id(self, malware_type: str) -> str:
        prefix_map = {
            'ransomware': 'RAN',
            'trojan': 'TRJ',
            'rootkit': 'RTK',
            'bootkit': 'BTK',
            'spyware': 'SPY',
            'worm': 'WRM',
            'banker': 'BNK',
            'loader': 'LDR',
            'miner': 'MIN',
            'exploit': 'EXP',
            'generic': 'GEN',
            'suspicious': 'SUS',
            'documentation': 'DOC',
            'unknown': 'REC',
        }
        prefix = prefix_map.get(malware_type, 'REC')
        self.counters[prefix] = self.counters.get(prefix, 0) + 1
        return f"{prefix}-{self.counters[prefix]:03d}"

    def build_record(self, document: Dict) -> Dict:
        text = document.get('cleaned_text') or document.get('raw_text', '')
        filename = document.get('filename', '')

        adapted = self.adapter.adapt(document)

        # Extraire d'abord les règles YARA (nécessaires pour family/type)
        yara_rules_list = self.extractor.extract_yara_rules(text)
        yara_text_sample = yara_rules_list[0] if yara_rules_list else ''

        if adapted.get('yara_rule'):
            yara_rule = adapted['yara_rule']
        elif yara_rules_list:
            yara_rule = '\n\n'.join(yara_rules_list)
        else:
            yara_rule = ''

        # FIX v3: passer filename + yara_text aux extracteurs
        malware_family = (
            adapted.get('malware_family')
            or self.extractor.extract_malware_family(
                text, filename=filename, yara_text=yara_text_sample
            or self.extractor.extract_family_from_source_filename(filename)
            )
        )

        malware_type = (
            adapted.get('malware_type')
            or self.extractor.extract_malware_type(
                text, filename=filename, yara_text=yara_text_sample
            )
        )
        # v4: si le texte décrit un outil légitime, ne pas classer ransomware
        if malware_type == 'ransomware' and self.extractor._is_likely_legit_tool(text):
            malware_type = 'unknown'

        behavior_summary = adapted.get('behavior_summary') or self.extractor.extract_behaviors(text)
        attack_stage = adapted.get('attack_stage') or self.extractor.extract_attack_stage(text)
        ioc = adapted.get('ioc') or self.extractor.extract_iocs(text)
        rule_conditions = adapted.get('rule_conditions') or []
        strings_or_patterns = adapted.get('strings_or_patterns') or []

        # Description : priorité à la meta: YARA, puis texte sémantique
        if adapted.get('description') and len(adapted['description']) > 50:
            description = adapted['description'][:600]
        elif yara_text_sample:
            description = self._description_from_yara_meta(yara_text_sample) or \
                          self.extractor.extract_best_sentences(text, n=2) or \
                          self._fallback_description(text)
        else:
            description = self.extractor.extract_best_sentences(text, n=2) or \
                          self._fallback_description(text)

        record = {
            "id": "",
            "description": description,
            "malware_family": malware_family,
            "malware_type": malware_type,
            "behavior_summary": behavior_summary,
            "attack_stage": attack_stage,
            "ioc": ioc,
            "yara_rule": yara_rule,
            "rule_conditions": rule_conditions,
            "strings_or_patterns": strings_or_patterns,
            "source_document": filename,
            "confidence": "",
            "notes_on_fp": "",
            "language": self._detect_language(text),
            "embedding_text": "",
            "source_type": adapted.get('source_type', 'unknown'),
            "yara_rules_count": len(yara_rules_list),
        }

        if record['yara_rule'] and not record['rule_conditions']:
            record['rule_conditions'] = self.extractor.extract_rule_conditions(record['yara_rule'])

        if not record['strings_or_patterns']:
            record['strings_or_patterns'] = self.extractor.extract_strings_patterns(text)

        record['id'] = self._make_id(record['malware_type'])
        record['confidence'] = self._compute_confidence(record)
        record['notes_on_fp'] = self._generate_fp_notes(record)

        return record

    def _description_from_yara_meta(self, yara_text: str) -> str:
        """Extrait le champ description du bloc meta: YARA."""
        meta_match = re.search(r'meta\s*:(.*?)(?:strings\s*:|condition\s*:)', yara_text, re.DOTALL)
        if not meta_match:
            return ''
        meta_block = meta_match.group(1)
        match = re.search(r'description\s*=\s*"([^"]+)"', meta_block, re.IGNORECASE)
        if match:
            desc = match.group(1).strip()
            if len(desc) > 20:
                return desc
        return ''

    def _fallback_description(self, text: str) -> str:
        paragraphs = [p.strip() for p in text.split('\n\n') if len(p.strip()) > 60]
        for p in paragraphs:
            if not re.match(r'^(\d+[\.\)]\s|\•\s|-\s)', p.strip()):
                return p[:500]
        return paragraphs[0][:500] if paragraphs else "No description available"

    def _compute_confidence(self, record: Dict) -> str:
        score = 0
        if record.get('malware_family') and record['malware_family'] != 'unknown':
            score += 1
        if record.get('malware_type') and record['malware_type'] not in ('unknown', 'generic', 'suspicious'):
            score += 1
        if record.get('ioc') and len(record['ioc']) >= 3:
            score += 1
        if record.get('behavior_summary') and len(record['behavior_summary']) >= 2:
            score += 1
        if record.get('yara_rule') and len(record['yara_rule']) > 80:
            score += 2
        if record.get('attack_stage') and record['attack_stage'] != 'unknown':
            score += 1
        if record.get('strings_or_patterns') and len(record['strings_or_patterns']) >= 2:
            score += 1
        if score >= 5:
            return "high"
        elif score >= 3:
            return "medium"
        else:
            return "low"

    def _generate_fp_notes(self, record: Dict) -> str:
        notes = []
        if record.get('malware_type') == 'ransomware':
            notes.append("May match legitimate encryption tools if entropy alone is used")
        if 'entropy' in str(record.get('rule_conditions', '')):
            notes.append("High entropy can match packed legitimate software")
        if not record.get('ioc'):
            notes.append("No IOCs extracted — rule may be too generic")
        if record.get('malware_type') == 'rootkit':
            notes.append("Kernel-level hooks may match legitimate drivers")
        if record.get('yara_rules_count', 0) > 1:
            notes.append(f"Record contains {record['yara_rules_count']} YARA rules — consider splitting per rule")
        return " | ".join(notes) if notes else ""

    def _detect_language(self, text: str) -> str:
        try:
            sample = text[100:1100] if len(text) > 1100 else text
            return detect(sample)
        except Exception:
            return "en"