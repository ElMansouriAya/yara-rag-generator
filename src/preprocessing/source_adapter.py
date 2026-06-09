# src/preprocessing/source_adapter.py
# v4 — corrections critiques :
#   1. Passe yara_text aux extracteurs de family/type
#   2. _infer_type_from_yara() enrichi avec plus de patterns
#   3. Filtre des faux IOCs dans les rapports par contexte
#   4. _generate_desc_from_yara() gère le snake_case
#   5. _parse_yara_conditions() capture les nombres
#   6. Inférence attack_stage depuis le type de règle

import re
from typing import Dict, List, Optional


class SourceAdapter:
    """Adapte l'extraction selon le type de source (dossier du Drive)."""
    
    def __init__(self, entity_extractor=None):
        self.extractor = entity_extractor
    
    def adapt(self, document: Dict) -> Dict:
        """Route vers le bon extracteur selon le dossier source."""
        folder = document.get('source_folder', '')
        filename = document.get('filename', '').lower()
        
        # --- RAPPORTS MALWARE ---
        if 'Rapports malware' in folder:
            return self._adapt_malware_reports(document)
        
        # --- RÈGLES YARA (3 dossiers) ---
        elif 'rules-yara-cybersecurity' in folder:
            return self._adapt_yara_cybersecurity(document)
        elif folder.endswith('rules') or folder.endswith('/rules'):
            if 'cybersecurity' not in folder:
                return self._adapt_yara_rules(document)
        
        # --- YARA (dossier général) ---
        elif 'yara' in folder and 'YARA' not in folder and 'csv' not in folder and 'json' not in folder and 'doc' not in folder:
            return self._adapt_yara_general(document)
        
        # --- THREAT INTELLIGENCE & IOC ---
        elif 'Threat intelligence' in folder or 'IOC' in folder:
            return self._adapt_threat_intel(document)
        
        # --- DONNÉES STRUCTURÉES ---
        elif 'csv' in folder.lower() or 'json' in folder.lower():
            return self._adapt_structured(document)
        
        # --- DOCUMENTATION YARA ---
        elif 'Documentations' in folder or 'documentation' in folder.lower():
            return self._adapt_yara_docs(document)
        
        else:
            return self._adapt_generic(document)
    
    # ═══════════════════════════════════════════════════════
    # 1. RAPPORTS MALWARE — FILTRAGE IOCs AMÉLIORÉ
    # ═══════════════════════════════════════════════════════
    def _adapt_malware_reports(self, document: Dict) -> Dict:
        text = document.get('raw_text', '')
        filename = document.get('filename', '')
        
        # Filtrer les faux IOCs des exercices/livres
        raw_iocs = self._extract_all_iocs(text) if self.extractor else []
        filtered_iocs = self._filter_report_iocs(raw_iocs, text, filename)
        
        return {
            'description': self._extract_executive_summary(text),
            'malware_family': self._extract_family_from_report(text),
            'malware_type': self._extract_type_from_report(text),
            'behavior_summary': self._extract_behaviors_from_report(text),
            'attack_stage': self._extract_stage_from_report(text),
            'ioc': filtered_iocs,
            'yara_rule': self._extract_yara_from_report(text),
            'rule_conditions': [],
            'strings_or_patterns': [],
            'source_type': 'malware_report',
            'confidence': 'medium'
        }
    
    def _filter_report_iocs(self, iocs: List[str], text: str, filename: str) -> List[str]:
        """Filtre les faux IOCs des rapports d'exercices/livres."""
        if not iocs:
            return []
        
        # Blacklist de faux domaines/chemins (exercices, références)
        false_positive_patterns = [
            r'practicalmalwareanalysis\.com',
            r'malwareanalysisbook\.com',
            r'nostarch\.com',
            r'informit\.com',
            r'gnome\.org',
            r'packetstormsecurity\.net',
            r'virustotal\.com',
            r'google\.com',
            r'yahoo\.com',
            r'wikipedia\.org',
            r'example\.com',
            r'microsoft\.com',
            r'adobe\.com',
            r'oracle\.com',
            r'cisco\.com',
            r'intel\.com',
            r'openssl\.org',
            r'python\.org',
            r'wireshark\.org',
            r'vmware\.com',
            r'sourceforge\.net',
            r'github\.com',  # Seulement dans les rapports, pas les YARA
            r'flaticon\.com',
            r'w3\.org',
            r'eff\.org',
            r'Lab\d+-\d+',  # Fichiers d'exercices
            r'C:\\\\Windows\\\\System32\\\\(?:kernel32|user32|ntdll|advapi32|gdi32|ws2_32|shell32|msvcrt)\.(?:dll|exe)',
            r'C:\\\\Windows\\\\System32\\\\winhlp2\.exe',
            r'C:\\\\WINDOWS\\\\system32\\\\sol\.exe',
            r'C:\\\\WINDOWS\\\\system32\\\\cmd\.exe',
            r'C:\\\\Program Files\\\\Internet Explorer\\\\iexplore\.exe',
            r'C:\\\\Program Files\\\\VMware',
            r'C:\\\\Program Files\\\\Immunity Inc',
            r'C:\\\\Users\\\\User1',
            r'C:\\\\Documents and Settings\\\\user\\\\Desktop',
            r'C:\\\\Temp\\\\cc\.exe',
            r'C:\\\\Windows\\\\evil\.exe',
            r'C:\\\\Windows\\\\system32\\\\vmnat\.exe',
            r'C:\\\\Windows\\\\System32\\\\kerne132\.dll',  # Faux nom d'exercice
            r'C:\\\\Windows\\\\System32\\\\kernel64x\.dll',
            r'C:\\\\Windows\\\\System32\\\\inet_epar32\.dll',
            r'C:\\\\Windows\\\\System32\\\\Mlwx486\.sys',
            r'C:\\\\Windows\\\\System32\\\\wupdmgr\.exe',
            r'z:\\\\Malware',
            r'c:\\\\websymbols',
            r'c:\\\\myfile\.txt',
            r'c:\\\\tempdownload\.exe',
        ]
        
        filtered = []
        for ioc in iocs:
            is_fp = False
            for pattern in false_positive_patterns:
                if re.search(pattern, ioc, re.IGNORECASE):
                    is_fp = True
                    break
            
            # Filtrer les chemins Windows standards système
            if re.match(r'C:\\\\Windows\\\\System32\\\\\w+\.(dll|exe)$', ioc, re.IGNORECASE):
                if not any(mal in ioc.lower() for mal in ['evil', 'mal', 'hack', 'crack', 'patch']):
                    is_fp = True
            
            # Filtrer les IPs privées/locales
            if re.match(r'(?:127|10|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d+\.\d+\.\d+', ioc):
                is_fp = True
            
            if not is_fp:
                filtered.append(ioc)
        
        return filtered
    
    # ═══════════════════════════════════════════════════════
    # 2. RÈGLES YARA - CYBERSECURITY — FAMILY/TYPE CORRIGÉS
    # ═══════════════════════════════════════════════════════
    def _adapt_yara_cybersecurity(self, document: Dict) -> Dict:
        text = document.get('raw_text', '')
        filename = document.get('filename', '')
        
        rule_name = self._extract_rule_name_from_filename(filename)
        yara_rule = text if self._is_valid_yara(text) else ""
        
        # FIX v4: Passer yara_text aux extracteurs
        family = "unknown"
        mtype = "unknown"
        if yara_rule and self.extractor:
            family = self.extractor.extract_malware_family(
                text="", filename=filename, yara_text=yara_rule
            )
            mtype = self.extractor.extract_malware_type(
                text="", filename=filename, yara_text=yara_rule
            )
        
        # Fallback si l'extracteur retourne unknown
        if family == "unknown":
            family = self._extract_family_from_yara(yara_rule, filename)
        if mtype == "unknown":
            mtype = self._infer_type_from_yara(yara_rule, filename)
        
        # Inférer le stage d'attaque
        attack_stage = self._infer_attack_stage_from_type(mtype, yara_rule)
        
        # Extraire les IOCs depuis la règle YARA (hash, URLs)
        iocs = self._extract_iocs_from_yara(yara_rule)
        
        return {
            'description': self._generate_desc_from_yara(yara_rule, rule_name),
            'malware_family': family,
            'malware_type': mtype,
            'behavior_summary': self._infer_behaviors_from_yara(yara_rule, mtype),
            'attack_stage': attack_stage,
            'ioc': iocs,
            'yara_rule': yara_rule,
            'rule_conditions': self._parse_yara_conditions(yara_rule),
            'strings_or_patterns': self._parse_yara_strings(yara_rule),
            'source_type': 'yara_cybersecurity_rule',
            'confidence': self._compute_yara_confidence(yara_rule, family, mtype)
        }
    
    # ═══════════════════════════════════════════════════════
    # 3. RÈGLES YARA - GÉNÉRAL
    # ═══════════════════════════════════════════════════════
    def _adapt_yara_rules(self, document: Dict) -> Dict:
        text = document.get('raw_text', '')
        filename = document.get('filename', '')
        
        yara_rule = text if self._is_valid_yara(text) else ""
        
        family = "unknown"
        mtype = "unknown"
        if yara_rule and self.extractor:
            family = self.extractor.extract_malware_family(
                text="", filename=filename, yara_text=yara_rule
            )
            mtype = self.extractor.extract_malware_type(
                text="", filename=filename, yara_text=yara_rule
            )
        
        if family == "unknown":
            family = self._extract_family_from_yara(yara_rule, filename)
        if mtype == "unknown":
            mtype = self._infer_type_from_yara(yara_rule, filename)
        
        attack_stage = self._infer_attack_stage_from_type(mtype, yara_rule)
        iocs = self._extract_iocs_from_yara(yara_rule)
        
        return {
            'description': self._generate_desc_from_yara(yara_rule, filename),
            'malware_family': family,
            'malware_type': mtype,
            'behavior_summary': self._infer_behaviors_from_yara(yara_rule, mtype),
            'attack_stage': attack_stage,
            'ioc': iocs,
            'yara_rule': yara_rule,
            'rule_conditions': self._parse_yara_conditions(yara_rule),
            'strings_or_patterns': self._parse_yara_strings(yara_rule),
            'source_type': 'yara_rule',
            'confidence': self._compute_yara_confidence(yara_rule, family, mtype)
        }
    
    # ═══════════════════════════════════════════════════════
    # 4. YARA - DOSSIER GÉNÉRAL
    # ═══════════════════════════════════════════════════════
    def _adapt_yara_general(self, document: Dict) -> Dict:
        text = document.get('raw_text', '')
        filename = document.get('filename', '')
        
        if self._is_valid_yara(text):
            return self._adapt_yara_rules(document)
        
        return {
            'description': self._extract_first_paragraph(text),
            'malware_family': self._extract_family_from_text(text),
            'malware_type': 'unknown',
            'behavior_summary': [],
            'attack_stage': 'unknown',
            'ioc': self._extract_all_iocs(text),
            'yara_rule': self._extract_yara_rule_from_text(text),
            'rule_conditions': [],
            'strings_or_patterns': [],
            'source_type': 'yara_misc',
            'confidence': 'low'
        }
    
    # ═══════════════════════════════════════════════════════
    # 5. THREAT INTELLIGENCE & IOC
    # ═══════════════════════════════════════════════════════
    def _adapt_threat_intel(self, document: Dict) -> Dict:
        text = document.get('raw_text', '')
        doc_type = document.get('doc_type', '')
        
        if doc_type in ('csv', 'json'):
            return self._adapt_structured(document)
        
        return {
            'description': self._extract_summary(text),
            'malware_family': self._extract_family_from_text(text),
            'malware_type': self._extract_type_from_text(text),
            'behavior_summary': self._extract_ttp_from_intel(text),
            'attack_stage': self._extract_stage_from_intel(text),
            'ioc': self._extract_all_iocs(text),
            'yara_rule': self._extract_yara_rule_from_text(text),
            'rule_conditions': [],
            'strings_or_patterns': self._extract_patterns_from_intel(text),
            'source_type': 'threat_intelligence',
            'confidence': 'medium'
        }
    
    # ═══════════════════════════════════════════════════════
    # 6. DONNÉES STRUCTURÉES (CSV/JSON)
    # ═══════════════════════════════════════════════════════
    def _adapt_structured(self, document: Dict) -> Dict:
        data = document.get('structured_data', {})
        
        if isinstance(data, list) and len(data) > 0:
            first_row = data[0]
            return {
                'description': first_row.get('description', first_row.get('desc', '')),
                'malware_family': first_row.get('malware_family', first_row.get('family', 'unknown')),
                'malware_type': first_row.get('malware_type', first_row.get('type', 'unknown')),
                'behavior_summary': self._parse_list_field(first_row.get('behavior_summary', '')),
                'attack_stage': first_row.get('attack_stage', 'unknown'),
                'ioc': self._parse_list_field(first_row.get('ioc', '')),
                'yara_rule': first_row.get('yara_rule', first_row.get('rule', '')),
                'rule_conditions': self._parse_list_field(first_row.get('rule_conditions', '')),
                'strings_or_patterns': self._parse_list_field(first_row.get('strings_or_patterns', '')),
                'source_type': 'structured_data',
                'confidence': first_row.get('confidence', 'medium')
            }
        
        elif isinstance(data, dict):
            return {
                'description': data.get('description', ''),
                'malware_family': data.get('malware_family', 'unknown'),
                'malware_type': data.get('malware_type', 'unknown'),
                'behavior_summary': data.get('behavior_summary', []),
                'attack_stage': data.get('attack_stage', 'unknown'),
                'ioc': data.get('ioc', []),
                'yara_rule': data.get('yara_rule', ''),
                'rule_conditions': data.get('rule_conditions', []),
                'strings_or_patterns': data.get('strings_or_patterns', []),
                'source_type': 'structured_data',
                'confidence': data.get('confidence', 'medium')
            }
        
        return self._adapt_generic(document)
    
    # ═══════════════════════════════════════════════════════
    # 7. DOCUMENTATION YARA
    # ═══════════════════════════════════════════════════════
    def _adapt_yara_docs(self, document: Dict) -> Dict:
        text = document.get('raw_text', '')
        
        code_blocks = self._extract_code_blocks(text)
        yara_examples = self._extract_yara_examples(text)
        
        return {
            'description': self._extract_doc_description(text),
            'malware_family': 'yara_documentation',
            'malware_type': 'documentation',
            'behavior_summary': ['yara syntax', 'rule writing', 'pattern matching'],
            'attack_stage': 'unknown',
            'ioc': [],
            'yara_rule': yara_examples[0] if yara_examples else "",
            'rule_conditions': self._extract_doc_conditions(text),
            'strings_or_patterns': self._extract_doc_patterns(text),
            'source_type': 'yara_documentation',
            'confidence': 'high'
        }
    
    # ═══════════════════════════════════════════════════════
    # 8. FALLBACK GÉNÉRIQUE
    # ═══════════════════════════════════════════════════════
    def _adapt_generic(self, document: Dict) -> Dict:
        text = document.get('raw_text', '')
        
        return {
            'description': self._extract_first_paragraph(text),
            'malware_family': 'unknown',
            'malware_type': 'unknown',
            'behavior_summary': [],
            'attack_stage': 'unknown',
            'ioc': self._extract_all_iocs(text),
            'yara_rule': self._extract_yara_rule_from_text(text),
            'rule_conditions': [],
            'strings_or_patterns': [],
            'source_type': 'generic',
            'confidence': 'low'
        }
    
    # ═══════════════════════════════════════════════════════
    # MÉTHODES UTILITAIRES — CORRIGÉES v4
    # ═══════════════════════════════════════════════════════
    
    def _is_valid_yara(self, text: str) -> bool:
        return bool(re.search(r'rule\s+\w+\s*\{', text))
    
    def _extract_rule_name_from_filename(self, filename: str) -> str:
        name = filename.replace('.yar', '').replace('.yara', '').replace('.rule', '')
        name = re.sub(r'[_-]', ' ', name)
        return name.strip().title()
    
    def _generate_desc_from_yara(self, yara_rule: str, rule_name: str) -> str:
        """Génère une description depuis une règle YARA — FIX snake_case."""
        if not yara_rule:
            return f"YARA rule: {rule_name}"
        
        # Extraire les commentaires
        comments = re.findall(r'//\s*(.+)', yara_rule)
        if comments:
            return comments[0].strip()
        
        # Extraire description depuis meta:
        meta_match = re.search(r'meta\s*:(.*?)(?:strings\s*:|condition\s*:)', yara_rule, re.DOTALL)
        if meta_match:
            desc_match = re.search(r'description\s*=\s*"([^"]+)"', meta_match.group(1), re.IGNORECASE)
            if desc_match:
                return desc_match.group(1).strip()
        
        # Extraire les strings pour la description
        strings = self._parse_yara_strings(yara_rule)
        readable_strings = [s for s in strings if not s.startswith('hex:') and not s.startswith('regex:') and len(s) > 3]
        
        # Convertir rule_name snake_case en titre lisible
        readable_name = rule_name.replace('_', ' ').title()
        
        if readable_strings:
            patterns_str = ', '.join(readable_strings[:3])
            return f"YARA rule {readable_name} detecting patterns: {patterns_str}"
        
        return f"YARA detection rule for {readable_name}"
    
    def _extract_family_from_yara(self, yara_rule: str, filename: str) -> str:
        """Extrait la famille depuis une règle YARA — fallback si extracteur échoue."""
        # Depuis le nom de la règle
        rule_match = re.search(r'rule\s+(\w+)', yara_rule)
        if rule_match:
            rule_name = rule_match.group(1).lower()
            
            # Mapping direct des noms de règles connus
            family_mappings = {
                'eleonore': 'Eleonore',
                'fragus': 'Fragus',
                'crimepack': 'CrimePack',
                'blackhole': 'BlackHole',
                'cool': 'CoolEK',
                'neutrino': 'Neutrino',
                'angler': 'Angler',
                'nuclear': 'Nuclear',
                'rig': 'Rig',
                'sundown': 'Sundown',
                'magnitude': 'Magnitude',
                'fiesta': 'Fiesta',
                'sweetorange': 'SweetOrange',
                'styx': 'Styx',
                'redkit': 'RedKit',
                'whitehole': 'WhiteHole',
            }
            
            for key, family in family_mappings.items():
                if key in rule_name or key in filename.lower():
                    return family
            
            # Chercher les familles connues
            known_families = [
                'LockBit', 'Ryuk', 'Emotet', 'TrickBot', 'Conti',
                'REvil', 'DarkSide', 'WannaCry', 'Dridex', 'Qakbot',
                'IcedID', 'CobaltStrike', 'Mimikatz', 'Cerber',
                'CryptoLocker', 'BlackMatter', 'Hive', 'BlackCat', 'Clop',
                'Maze', 'Sodinokibi', 'GandCrab', 'Dharma', 'Phobos',
                'Locky', 'Cryptowall', 'TeslaCrypt', 'Royal', 'Play',
                'Cuba', 'Ragnar', 'MedusaLocker', 'Babuk', 'Avaddon',
                'Grief', 'Prometheus', 'AgentTesla', 'FormBook', 'Remcos',
                'AsyncRAT', 'NjRAT', 'QuasarRAT', 'DarkComet', 'PoisonIvy',
                'PlugX', 'Gh0stRAT', 'NetWire', 'BitRAT', 'XWorm',
                'Warzone', 'NanoCore', 'Stuxnet', 'Duqu', 'Flame',
                'Regin', 'ProjectSauron', 'BlackEnergy', 'GreyEnergy',
                'Industroyer', 'Triton', 'FancyBear', 'CozyBear',
                'Turla', 'Lazarus', 'Carbanak', 'FIN7', 'OceanLotus',
                'SideWinder', 'MuddyWater', 'Gamaredon', 'HiddenCobra',
                'DarkHotel', 'OilRig', 'Conficker', 'Mirai', 'Mariposa',
                'Storm', 'RayInitiator', 'LineViper', 'LineDancer',
                'LineRunner', 'Autumn', 'Backdoor',
            ]
            
            for family in known_families:
                if family.lower() in rule_name or family.lower() in filename.lower():
                    return family
        
        return "unknown"
    
    def _infer_type_from_yara(self, yara_rule: str, filename: str = '') -> str:
        """Infère le type de malware depuis une règle YARA — enrichi v4."""
        yara_lower = yara_rule.lower()
        name_lower = filename.lower()
        combined = yara_lower + ' ' + name_lower
        
        # Patterns par type (ordre: plus spécifique d'abord)
        type_patterns = {
            'ransomware': [
                r'ransom', r'encrypt', r'locked', r'bitcoin', r'payment',
                r'\.locked', r'\.encrypt', r'decrypt_', r'ransom note',
                r'aes-256', r'your files have been',
            ],
            'exploit': [
                r'cve[_-]\d{4}[_-]\d+', r'exploit', r'vulnerability',
                r'remote code execution', r'rce', r'buffer overflow',
                r'heap spray', r'shellcode', r'0day', r'zero.?day',
                r'kit', r'jar', r'pdf', r'swf', r'flash',
            ],
            'loader': [
                r'loader', r'dropper', r'download', r'stage',
                r'payload loader', r'shellcode loader', r'downloader',
            ],
            'trojan': [
                r'trojan', r'backdoor', r'remote access', r'rat\b',
                r'remote admin', r'command and control', r'c2 server',
                r'beacon', r'apt', r'spy', r'keylog', r'credential',
                r'infostealer', r'stealer',
            ],
            'spyware': [
                r'spyware', r'keylogger', r'steal credentials',
                r'exfiltrate data', r'credential harvest',
                r'infostealer', r'password stealer', r'screenshot',
                r'clipboard monitor',
            ],
            'worm': [
                r'worm', r'self-replicate', r'self-propagat',
                r'spread across', r'usb spread', r'network share',
            ],
            'rootkit': [
                r'rootkit', r'kernel hook', r'bootkit', r'grub hook',
                r'uefi', r'hook lina', r'kernel module', r'ring0',
                r'driver inject', r'boot', r'kernel',
            ],
            'banker': [
                r'banking', r'financial fraud', r'transaction intercept',
                r'card skimmer', r'web inject', r'form grab',
            ],
            'miner': [
                r'miner', r'cryptocurrency mining', r'monero',
                r'cryptominer', r'xmrig', r'cpu usage', r'mining pool',
            ],
        }
        
        scores = {}
        for mtype, patterns in type_patterns.items():
            score = sum(1 for p in patterns if re.search(p, combined))
            if score > 0:
                scores[mtype] = score
        
        if scores:
            return max(scores, key=scores.get)
        
        # Inférence depuis le nom de fichier
        if 'jar' in name_lower or 'java' in name_lower:
            if 'exploit' in combined or 'cve' in combined:
                return 'exploit'
        if 'js' in name_lower and ('exploit' in combined or 'kit' in combined):
            return 'exploit'
        if 'pdf' in name_lower:
            return 'exploit'
        
        return "unknown"
    
    def _infer_attack_stage_from_type(self, mtype: str, yara_rule: str) -> str:
        """Infère le stage d'attaque depuis le type de malware."""
        stage_map = {
            'exploit': 'initial-access',
            'loader': 'execution',
            'trojan': 'execution',
            'ransomware': 'impact',
            'spyware': 'collection',
            'rootkit': 'defense-evasion',
            'worm': 'lateral-movement',
            'banker': 'credential-access',
            'miner': 'impact',
        }
        
        # Vérifier si la règle mentionne des stages spécifiques
        yara_lower = yara_rule.lower()
        if 'persist' in yara_lower or 'registry' in yara_lower or 'schtasks' in yara_lower:
            return 'persistence'
        if 'privilege' in yara_lower or 'uac' in yara_lower or 'token' in yara_lower:
            return 'privilege-escalation'
        if 'lateral' in yara_lower or 'psexec' in yara_lower or 'wmi' in yara_lower:
            return 'lateral-movement'
        if 'credential' in yara_lower or 'mimikatz' in yara_lower or 'lsass' in yara_lower:
            return 'credential-access'
        if 'exfil' in yara_lower or 'upload' in yara_lower or 'dns tunnel' in yara_lower:
            return 'exfiltration'
        
        return stage_map.get(mtype, 'unknown')
    
    def _infer_behaviors_from_yara(self, yara_rule: str, mtype: str) -> List[str]:
        """Infère les comportements depuis une règle YARA."""
        behaviors = []
        yara_lower = yara_rule.lower()
        
        behavior_map = {
            'shellcode execution': [r'shellcode', r'exec shellcode', r'shellcode loader'],
            'network communication': [r'c2', r'command and control', r'beacon', r'http', r'url'],
            'file encryption': [r'encrypt', r'cipher', r'aes', r'rsa'],
            'process injection': [r'inject', r'hollow', r'apc', r'dll inject'],
            'registry modification': [r'registry', r'hkey_', r'reg add'],
            'persistence via scheduled task': [r'schtasks', r'scheduled task', r'startup'],
            'anti-analysis': [r'vm check', r'sandbox', r'debugger', r'anti-forensic'],
            'data exfiltration': [r'exfiltrate', r'upload', r'ftp', r'dns tunnel'],
            'credential harvesting': [r'credential', r'password', r'lsass', r'mimikatz'],
            'bootkit/rootkit activity': [r'bootkit', r'rootkit', r'kernel', r'uefi', r'grub'],
            'anti-forensics': [r'log wipe', r'syslog', r'memory wipe', r'core dump'],
            'lateral movement': [r'lateral', r'psexec', r'wmiexec', r'smbexec'],
        }
        
        for behavior, patterns in behavior_map.items():
            if any(re.search(p, yara_lower) for p in patterns):
                behaviors.append(behavior)
        
        # Comportements par défaut selon le type
        default_behaviors = {
            'ransomware': ['file encryption'],
            'trojan': ['network communication'],
            'exploit': ['shellcode execution'],
            'rootkit': ['bootkit/rootkit activity', 'anti-forensics'],
            'spyware': ['credential harvesting', 'data exfiltration'],
            'loader': ['shellcode execution'],
        }
        
        if not behaviors and mtype in default_behaviors:
            behaviors = default_behaviors[mtype]
        
        return behaviors
    
    def _extract_iocs_from_yara(self, yara_rule: str) -> List[str]:
        """Extrait les IOCs depuis une règle YARA (hash, URLs, emails)."""
        iocs = []
        
        # Hash dans meta:
        hash_patterns = [
            r'hash\d*\s*=\s*"([a-fA-F0-9]{32,64})"',
            r'md5\s*=\s*"([a-fA-F0-9]{32})"',
            r'sha1\s*=\s*"([a-fA-F0-9]{40})"',
            r'sha256\s*=\s*"([a-fA-F0-9]{64})"',
        ]
        for pattern in hash_patterns:
            matches = re.findall(pattern, yara_rule, re.IGNORECASE)
            iocs.extend(matches)
        
        # URLs dans strings
        url_pattern = r'https?://[^\s"\'<>]+'
        urls = re.findall(url_pattern, yara_rule)
        # Filtrer les URLs de référence (github, pastebin)
        ref_urls = [u for u in urls if any(ref in u.lower() for ref in ['github.com', 'pastebin.com', 'gist.github.com'])]
        iocs.extend(ref_urls)
        
        # Emails dans meta:
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        emails = re.findall(email_pattern, yara_rule)
        iocs.extend(emails)
        
        # Domaines suspects (pas les références)
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|gov|edu|io|uk|de|fr|ru|cn|jp|au|ca|br|in|us|mil|int|eu|co|info|biz|onion)\b'
        domains = re.findall(domain_pattern, yara_rule)
        # Filtrer les domaines de référence connus
        ref_domains = {'github.com', 'pastebin.com', 'gist.github.com', 'virustotal.com'}
        suspicious_domains = [d for d in domains if d.lower() not in ref_domains and not d.startswith('www.')]
        iocs.extend(suspicious_domains)
        
        return list(dict.fromkeys(iocs))
    
    def _compute_yara_confidence(self, yara_rule: str, family: str, mtype: str) -> str:
        """Calcule la confiance pour une règle YARA."""
        score = 0
        
        if yara_rule and len(yara_rule) > 100:
            score += 1
        if 'meta' in yara_rule.lower():
            score += 1
        if 'author' in yara_rule.lower():
            score += 1
        if 'date' in yara_rule.lower():
            score += 1
        if family and family != 'unknown':
            score += 1
        if mtype and mtype != 'unknown':
            score += 1
        if 'hash' in yara_rule.lower():
            score += 1
        if 'strings' in yara_rule.lower() and 'condition' in yara_rule.lower():
            score += 1
        
        if score >= 6:
            return 'high'
        elif score >= 4:
            return 'medium'
        else:
            return 'low'
    
    def _parse_yara_conditions(self, yara_rule: str) -> List[str]:
        """Extrait les conditions d'une règle YARA — FIX capture des nombres."""
        if not yara_rule:
            return []
        
        match = re.search(r'condition\s*:\s*(.*?)(?:\n\w+|\Z)', yara_rule, re.DOTALL)
        if not match:
            return []
        
        conditions_text = match.group(1)
        conditions = []
        
        # Patterns de conditions enrichis
        condition_patterns = [
            r'\b(filesize)\b',
            r'\b(uint16|uint32|uint8)\b',
            r'\b(entropy)\b',
            r'\b(pe\.imphash)\b',
            r'\b(pe\.section)\b',
            r'\b(math\.entropy)\b',
            r'\b(for\s+any)\b',
            r'\b(all\s+of)\b',
            r'\b(any\s+of)\b',
            r'\b(none\s+of)\b',
            r'\b(\d+\s+of\s+them)\b',  # FIX: capture "12 of them", "2 of them"
            r'\b(\d+\s+of\s+\(\$[a-zA-Z0-9_]+\*\))\b',  # "2 of ($b*)"
            r'\b(#\w+)\b',
            r'\b(@\w+)\b',
            r'\b(\$\w+)\b',  # Variables de strings
        ]
        
        for pattern in condition_patterns:
            matches = re.findall(pattern, conditions_text, re.IGNORECASE)
            conditions.extend(matches)
        
        # Nettoyer et dédupliquer
        conditions = list(dict.fromkeys(c.strip() for c in conditions if c.strip()))
        return conditions
    
    def _parse_yara_strings(self, yara_rule: str) -> List[str]:
        """Extrait les strings d'une règle YARA."""
        if not yara_rule:
            return []
        
        match = re.search(r'strings\s*:\s*(.*?)(?:condition|\Z)', yara_rule, re.DOTALL)
        if not match:
            return []
        
        strings_text = match.group(1)
        strings = []
        
        # Strings entre guillemets (avec ascii wide nocase fullword)
        quoted = re.findall(r'=\s*"([^"]+)"(?:\s+(?:ascii|wide|nocase|fullword))*\s*$', strings_text, re.MULTILINE)
        strings.extend(quoted)
        
        # Strings hex
        hex_strings = re.findall(r'=\s*\{([0-9A-Fa-f\s]+)\}', strings_text)
        strings.extend([f"hex:{h.strip()}" for h in hex_strings])
        
        # Regex
        regex_strings = re.findall(r'=\s*/(.+?)/(?:\s+(?:ascii|wide|nocase|fullword))*\s*$', strings_text, re.MULTILINE)
        strings.extend([f"regex:{r}" for r in regex_strings])
        
        return list(dict.fromkeys(strings))
    
    def _extract_family_from_report(self, text: str) -> str:
        if self.extractor:
            return self.extractor.extract_malware_family(text)
        return "unknown"
    
    def _extract_type_from_report(self, text: str) -> str:
        if self.extractor:
            return self.extractor.extract_malware_type(text)
        return "unknown"
    
    def _extract_behaviors_from_report(self, text: str) -> List[str]:
        if self.extractor:
            return self.extractor.extract_behaviors(text)
        return []
    
    def _extract_stage_from_report(self, text: str) -> str:
        if self.extractor:
            return self.extractor.extract_attack_stage(text)
        return "unknown"
    
    def _extract_all_iocs(self, text: str) -> List[str]:
        if self.extractor:
            return self.extractor.extract_iocs(text)
        return []
    
    def _extract_yara_from_report(self, text: str) -> str:
        return self._extract_yara_rule_from_text(text)
    
    def _extract_yara_rule_from_text(self, text: str) -> str:
        pattern = r'rule\s+\w+(?:\s*:\s*[\w\s]+)?\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        match = re.search(pattern, text, re.DOTALL)
        return match.group(0) if match else ""
    
    def _extract_executive_summary(self, text: str) -> str:
        patterns = [
            r'(?:Executive\s+)?Summary[:\s]*\n(.*?)(?:\n\n|\Z)',
            r'Overview[:\s]*\n(.*?)(?:\n\n|\Z)',
            r'Introduction[:\s]*\n(.*?)(?:\n\n|\Z)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                summary = match.group(1).strip()
                if len(summary) > 50:
                    return summary[:500]
        return self._extract_first_paragraph(text)
    
    def _extract_first_paragraph(self, text: str) -> str:
        paragraphs = [p.strip() for p in text.split('\n\n') if len(p.strip()) > 50]
        return paragraphs[0][:500] if paragraphs else ""
    
    def _extract_summary(self, text: str) -> str:
        return self._extract_executive_summary(text)
    
    def _extract_family_from_text(self, text: str) -> str:
        if self.extractor:
            return self.extractor.extract_malware_family(text)
        return "unknown"
    
    def _extract_type_from_text(self, text: str) -> str:
        if self.extractor:
            return self.extractor.extract_malware_type(text)
        return "unknown"
    
    def _extract_ttp_from_intel(self, text: str) -> List[str]:
        ttp_keywords = {
            'initial access': ['phishing', 'spear-phishing', 'drive-by', 'exploit public'],
            'execution': ['powershell', 'cmd.exe', 'wscript', 'mshta'],
            'persistence': ['registry run', 'scheduled task', 'service'],
            'privilege escalation': ['uac bypass', 'token', 'impersonation'],
            'defense evasion': ['obfuscate', 'encode', 'packer', 'vm check'],
            'credential access': ['mimikatz', 'lsass', 'credential dump'],
            'discovery': ['systeminfo', 'net view', 'arp'],
            'lateral movement': ['psexec', 'wmi', 'smb', 'rdp'],
            'collection': ['archive', 'compress', 'screen capture'],
            'exfiltration': ['ftp', 'cloud', 'dns tunnel', 'c2'],
            'impact': ['encrypt', 'delete', 'wipe', 'ddos', 'ransom'],
        }
        
        behaviors = []
        text_lower = text.lower()
        for ttp, keywords in ttp_keywords.items():
            if any(kw in text_lower for kw in keywords):
                behaviors.append(ttp)
        return behaviors
    
    def _extract_stage_from_intel(self, text: str) -> str:
        ttps = self._extract_ttp_from_intel(text)
        return ttps[0] if ttps else "unknown"
    
    def _extract_patterns_from_intel(self, text: str) -> List[str]:
        patterns = []
        file_patterns = re.findall(r'\b\w+\.(exe|dll|bat|ps1|vbs|js)\b', text, re.IGNORECASE)
        patterns.extend(file_patterns)
        mutex_patterns = re.findall(r'mutex[:\s]+([^\s,;]+)', text, re.IGNORECASE)
        patterns.extend(mutex_patterns)
        reg_patterns = re.findall(r'HKEY_[A-Z_]+\\[^ \n]+', text)
        patterns.extend(reg_patterns)
        return list(set(patterns))
    
    def _extract_code_blocks(self, text: str) -> List[str]:
        blocks = re.findall(r'```(?:\w+)?\n(.*?)```', text, re.DOTALL)
        if not blocks:
            blocks = re.findall(r'<pre>(.*?)</pre>', text, re.DOTALL)
        return blocks
    
    def _extract_yara_examples(self, text: str) -> List[str]:
        examples = []
        code_blocks = self._extract_code_blocks(text)
        for block in code_blocks:
            if 'rule ' in block:
                examples.append(block)
        inline_rules = re.findall(r'rule\s+\w+\s*\{[^{}]*\}', text, re.DOTALL)
        examples.extend(inline_rules)
        return examples
    
    def _extract_doc_description(self, text: str) -> str:
        title_match = re.search(r'<h1[^>]*>(.*?)</h1>', text, re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
        return self._extract_first_paragraph(text)
    
    def _extract_doc_conditions(self, text: str) -> List[str]:
        conditions = []
        condition_keywords = ['filesize', 'uint16', 'uint32', 'entropy', 
                           'pe.imphash', 'pe.sections', 'math.entropy',
                           'for any', 'all of', 'any of', 'none of']
        text_lower = text.lower()
        for kw in condition_keywords:
            if kw in text_lower:
                conditions.append(kw)
        return conditions
    
    def _extract_doc_patterns(self, text: str) -> List[str]:
        examples = re.findall(r'"([^"]{3,})"', text)
        return list(set(examples))
    
    def _parse_list_field(self, value) -> List[str]:
        if isinstance(value, list):
            return value
        elif isinstance(value, str):
            if ',' in value:
                return [v.strip() for v in value.split(',')]
            elif value.strip():
                return [value.strip()]
        return []