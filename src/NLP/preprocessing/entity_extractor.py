# src/preprocessing/entity_extractor.py
# Pipeline d'extraction d'entités (famille, type, attaque) depuis le texte brut et les règles YARA.:

import re
from typing import List, Dict, Optional, Tuple

# ─── Blocklists globales ────────────────────────────────────────
_FILE_EXTENSIONS = {
    '.exe', '.dll', '.pdf', '.docx', '.txt', '.zip', '.py',
    '.js', '.html', '.htm', '.json', '.csv', '.xml', '.bat',
    '.ps1', '.vbs', '.png', '.jpg', '.gif', '.svg',
}

_VALID_TLDS = {
    'com', 'net', 'org', 'gov', 'edu', 'io', 'uk', 'de',
    'fr', 'ru', 'cn', 'jp', 'au', 'ca', 'br', 'in', 'us',
    'mil', 'int', 'eu', 'co', 'info', 'biz', 'onion',
}

_LOOPBACK_NETS = {'127.', '0.0.0.', '255.255.255.', '192.168.', '10.', '172.'}

_DOMAIN_FALSE_POSITIVES = {
    'version', 'release', 'build', 'patch', 'update', 'log',
    'null', 'none', 'true', 'false', 'localhost',
}

# Mots communs qui ne sont PAS des noms de famille de malware
_FAMILY_BLACKLIST = {
    'Detects', 'Detection', 'Detect', 'Unknown', 'The', 'This',
    'That', 'These', 'Such', 'New', 'Old', 'Any', 'All', 'Some',
    'Based', 'Used', 'Using', 'Found', 'Known', 'Named', 'Called',
    'Rule', 'Rules', 'Yara', 'File', 'Files', 'Code', 'Tool',
    'Stage', 'Version', 'Sample', 'Generic', 'Modified', 'Packed',
    'Injected', 'Encoded', 'Obfuscated', 'Encrypted', 'Signed',
    'Windows', 'Linux', 'MacOS', 'Android', 'Network', 'Memory',
    'Process', 'System', 'Service', 'Module', 'Driver', 'Library',
    'Microsoft', 'Adobe', 'Oracle', 'Cisco', 'Google', 'Apple',
}

# Mapping préfixe de fichier → type de malware
_FILENAME_TYPE_MAP = {
    'ran': 'ransomware',
    'ransom': 'ransomware',
    'crypt': 'ransomware',
    'locker': 'ransomware',
    'apt': 'trojan',       # APT → généralement trojan/backdoor
    'rat': 'trojan',
    'backdoor': 'trojan',
    'trojan': 'trojan',
    'troj': 'trojan',
    'mal': 'trojan',       # generic malware → trojan par défaut
    'spy': 'spyware',
    'spyw': 'spyware',
    'keylog': 'spyware',
    'infostealer': 'spyware',
    'stealer': 'spyware',
    'worm': 'worm',
    'vbs_': 'worm',        # beaucoup de worms VBS
    'rootkit': 'rootkit',
    'rtk': 'rootkit',
    'boot': 'rootkit',
    'bootkit': 'rootkit',
    'uefi': 'rootkit',
    'miner': 'miner',
    'coin': 'miner',
    'loader': 'loader',
    'dropper': 'loader',
    'drop': 'loader',
    'downloader': 'loader',
    'banker': 'banker',
    'bank': 'banker',
    'crime': 'trojan',
    'expl': 'exploit',
    'exploit': 'exploit',
    'gen': 'generic',
    'susp': 'suspicious',
}

# Mapping APT groups → famille connue
_APT_FAMILY_MAP = {
    'apt28': 'FancyBear',
    'apt29': 'CozyBear',
    'apt27': 'LuckyMouse',
    'apt1': 'Comment_Crew',
    'apt3': 'Gothic_Panda',
    'apt10': 'MenuPass',
    'apt30': 'LotusBlossom',
    'apt32': 'OceanLotus',
    'apt34': 'OilRig',
    'apt38': 'Lazarus',
    'apt41': 'Winnti',
    'cobaltgang': 'CobaltGroup',
    'lazarus': 'Lazarus',
    'sandworm': 'Sandworm',
    'turla': 'Turla',
    'equation': 'EquationGroup',
    'fancybear': 'FancyBear',
    'cozybear': 'CozyBear',
    'sidewinder': 'SideWinder',
    'twistedpanda': 'TwistedPanda',
    'blackenergy': 'BlackEnergy',
    'hiddencobra': 'HiddenCobra',
    'darkhotel': 'DarkHotel',
    'oceanlotus': 'OceanLotus',
    'carbanak': 'Carbanak',
    'fin7': 'FIN7',
    'fin6': 'FIN6',
    'muddywater': 'MuddyWater',
    'gamaredon': 'Gamaredon',
    'buhtrap': 'Buhtrap',
    'cozy': 'CozyBear',
    'fancy': 'FancyBear',
    'unc1151': 'Ghostwriter',
    'tran_duy_linh': 'TranDuyLinh',
    'sofacy': 'FancyBear',        # Sofacy = FancyBear/APT28
    'apt28': 'FancyBear',
    'xagent': 'FancyBear',
    'whitebear': 'Turla',
    'derusbi': 'Derusbi',
    'sakula': 'Sakula',
    'careto': 'Careto',
    'equationgroup': 'EquationGroup',
    'eqgrp': 'EquationGroup',
    'rokrat': 'RokRAT',
    'blackkingdom': 'BlackKingDom',
    'hangover': 'Hangover',
    'nazar': 'Nazar',
    'poweliks': 'Poweliks',
    'deputydog': 'DeputyDog',
    'alienspy': 'AlienSpy',
    'hworm': 'HWorm',
    'hizorat': 'HiZorRAT',
}


class EntityExtractor:
    def __init__(self):
        self.known_families = [
            # Ransomware
            'LockBit', 'Ryuk', 'Conti', 'REvil', 'DarkSide', 'WannaCry',
            'Petya', 'NotPetya', 'Cerber', 'CryptoLocker', 'BlackMatter',
            'Hive', 'BlackCat', 'Clop', 'Maze', 'Sodinokibi', 'GandCrab',
            'Dharma', 'Phobos', 'Locky', 'Cryptowall', 'TeslaCrypt',
            'LockBit3', 'LockBit4', 'Royal', 'Play', 'Cuba', 'Ragnar',
            'MedusaLocker', 'Babuk', 'Avaddon', 'Grief', 'Prometheus',
            # Trojans / RATs
            'Emotet', 'TrickBot', 'Dridex', 'Qakbot', 'IcedID',
            'AgentTesla', 'FormBook', 'Remcos', 'AsyncRAT', 'NjRAT',
            'QuasarRAT', 'DarkComet', 'PoisonIvy', 'PlugX', 'Gh0stRAT',
            'CobaltStrike', 'Metasploit', 'Mimikatz', 'BloodHound',
            'NetWire', 'BitRAT', 'XWorm', 'Warzone', 'NanoCore',
            # APT / nation-state
            'RayInitiator', 'LineViper', 'LineDancer', 'LineRunner',
            'Stuxnet', 'Duqu', 'Flame', 'Regin', 'ProjectSauron',
            'BlackEnergy', 'GreyEnergy', 'Industroyer', 'Triton',
            'FancyBear', 'CozyBear', 'Turla', 'Lazarus', 'Carbanak',
            'FIN7', 'OceanLotus', 'SideWinder', 'MuddyWater',
            'Gamaredon', 'HiddenCobra', 'DarkHotel', 'OilRig',
            # Worms / self-propagating
            'Conficker', 'WannaCry', 'Mirai', 'Mariposa', 'Storm',
            # Tools (détectés dans les YARA)
            'NSPPS', 'Gazer', 'ComRAT', 'REIGN', 'Coathanger',
            'BabbleLoader', 'XLogin',
            'RokRAT', 'Careto', 'BlackKingDom', 'Sfile', 'Derusbi',
            'Sakula', 'GhostShell', 'Hangover', 'EquationGroup',
            'Sofacy', 'WhiteBear', 'Poweliks', 'Pony', 'MacSpy',
            'XAgent', 'Nazar', 'HiZorRAT', 'AlienSpy', 'HWorm',
            'DeputyDog', 'Proton', 'ChaosRansomware', 'BlackGuard',
            'Jupyter', 'Onyx', 'Carbanak', 'TA410', 'Tendyron',
            'Fareit', 'Zbot', 'Zeus', 'SpyEye', 'Citadel',
            'Gozi', 'Ursnif', 'Danabot', 'Trickbot', 'ZLoader',
            'BazarLoader', 'Amadey', 'Lokibot', 'Azorult',
            'RedLine', 'Lumma', 'Phorpiex', 'Hancitor',
        ]

        self.malware_types = {
            'ransomware': [
                'ransom', 'encrypt files', 'locked files', 'decrypt', 'payment',
                'bitcoin', 'ransom note', '.locked', '.encrypt', 'decrypt_',
                'your files have been', 'aes-256', 'pay ransom',
            ],
            'trojan': [
                'trojan', 'backdoor', 'remote access', 'rat ', 'remote admin',
                'command and control', 'c2 server', 'beacon',
            ],
            'spyware': [
                'spyware', 'keylogger', 'steal credentials', 'exfiltrate data',
                'credential harvesting', 'infostealer', 'password stealer',
                'screenshot', 'clipboard monitor',
            ],
            'worm': [
                'worm', 'self-replicate', 'self-propagat', 'spread across',
                'usb spread', 'network share spread',
            ],
            'rootkit': [
                'rootkit', 'kernel hook', 'bookit', 'bootkit', 'grub hook',
                'uefi', 'hook lina', 'kernel module', 'ring0', 'driver inject',
            ],
            'banker': [
                'banking', 'financial fraud', 'transaction intercept',
                'card skimmer', 'web inject', 'form grab',
            ],
            'loader': [
                'shellcode loader', 'stage loader', 'dropper', 'payload loader',
                'first stage', 'second stage', 'download and execute',
            ],
            'miner': [
                'miner', 'cryptocurrency mining', 'monero', 'cryptominer',
                'xmrig', 'cpu usage', 'mining pool',
            ],
            'exploit': [
                'cve-', 'exploit', 'vulnerability', 'remote code execution',
                'rce', 'buffer overflow', 'heap spray',
            ],
        }

        self.attack_stages = {
            'initial-access': [
                'phishing', 'spear-phishing', 'drive-by', 'exploit public',
                'vpn exploit', 'email attachment', 'malicious macro',
            ],
            'execution': [
                'powershell', 'cmd.exe', 'wscript', 'mshta',
                'shellcode execution', 'vba macro', 'script execution',
            ],
            'persistence': [
                'registry run', 'scheduled task', 'service install',
                'startup', 'bootkit', 'grub hook', 'uefi persistence',
            ],
            'privilege-escalation': [
                'uac bypass', 'token impersonation', 'privilege escalation',
                'lpe', 'local privilege',
            ],
            'defense-evasion': [
                'obfuscat', 'base64 encod', 'packer', 'vm check',
                'anti-forensic', 'syslog suppress', 'amsi bypass',
                'etw bypass', 'process hollow',
            ],
            'credential-access': [
                'mimikatz', 'lsass dump', 'credential dump',
                'harvest credentials', 'pass the hash', 'kerberoast',
            ],
            'discovery': [
                'systeminfo', 'net view', 'arp scan', 'nmap',
                'reconnaissance', 'network discovery',
            ],
            'lateral-movement': [
                'psexec', 'wmiexec', 'smbexec', 'pass the hash', 'rdp',
                'lateral movement',
            ],
            'collection': [
                'archive files', 'compress data', 'screen capture',
                'cli harvest', 'keylog', 'clipboard',
            ],
            'exfiltration': [
                'ftp upload', 'dns tunnel', 'c2 exfil', 'icmp exfil',
                'vpn exfil', 'data exfiltration', 'upload to',
            ],
            'impact': [
                'encrypt files', 'delete shadows', 'wipe disk', 'ddos',
                'ransom note', 'delayed reboot', 'destroy data',
            ],
        }

        self.ioc_patterns = {
            'ip': r'(?<![/\w])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)',
            'domain': r'(?<![/\w])(?:www\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|gov|edu|io|uk|de|fr|ru|cn|jp|au|ca|br|in|us|mil|int|eu|co|info|biz|onion|ac)\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            'hash_md5': r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])',
            'hash_sha1': r'(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])',
            'hash_sha256': r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])',
            'win_path': r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+',
            'registry': r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s\n"\']+',
            'mutex': r'(?i)\bmutex[:\s]+([A-Za-z0-9_\-\.]{4,})',
            'suspicious_file': r'\b[A-Za-z0-9_\-]{3,}\.(?:exe|dll|bat|ps1|vbs|scr|pif|com)\b',
            'vssadmin': r'vssadmin(?:\.exe)?\s+delete\s+shadows[^\n]*',
        }

    # ─────────────────────────────────────────────
    # EXTRACTION FAMILLE — VERSION COMPLÈTE v3
    # ─────────────────────────────────────────────
    def extract_malware_family(self, text: str,
                                filename: str = '',
                                yara_text: str = '') -> str:
        """
        Stratégie en cascade :
        1. Méta YARA (champ author/family/malware_family dans meta:)
        2. Nom de la règle YARA (structuré comme apt_apt28_drovorub)
        3. Nom de fichier
        4. Liste known_families dans le texte
        5. Regex nom propre + mot-clé malware
        """
        # 1. Depuis les métadonnées YARA
        if yara_text:
            family = self._extract_from_yara_meta(yara_text)
            if family:
                return family

            # 2. Depuis le nom de la règle YARA
            family = self._extract_from_rule_name(yara_text)
            if family:
                return family

        # 3. Depuis le nom de fichier
        if filename:
            family = self._extract_from_filename_family(filename)
            if family:
                return family

        # 4. Liste known_families
        text_lower = text.lower()
        for family in self.known_families:
            if family.lower() in text_lower:
                return family

        # 5. Regex nom propre + mot-clé malware (avec blacklist)
        match = re.search(
            r'\b([A-Z][a-zA-Z0-9]{2,20})\s+(?:malware|ransomware|trojan|backdoor|worm|rootkit|botnet)',
            text
        )
        if match:
            candidate = match.group(1)
            if candidate not in _FAMILY_BLACKLIST:
                return candidate

        return "unknown"

    def _extract_from_yara_meta(self, yara_text: str) -> str:
        """v4: lire UNIQUEMENT malware_family/family/actor — PAS malware_type ni description."""
        meta_match = re.search(r'meta\s*:(.*?)(?:strings\s*:|condition\s*:)', yara_text, re.DOTALL)
        if not meta_match:
            return ''
        meta_block = meta_match.group(1)

        _GENERIC_TYPES = {
            'ADWARE', 'BACKDOOR', 'BOT', 'BOTNET', 'DOWNLOADER', 'DROPPER',
            'EXPLOIT', 'INFOSTEALER', 'KEYLOGGER', 'LOADER', 'MINER',
            'RAT', 'RANSOMWARE', 'ROOTKIT', 'SPYWARE', 'TROJAN', 'WORM',
            'UNKNOWN', 'MALWARE', 'N/A', 'VARIOUS', 'MULTIPLE', 'INFO',
        }

        for pattern in [
            r'(?:malware_family|family|actor|threat_name)\s*=\s*"([^"]+)"',
        ]:
            m = re.search(pattern, meta_block, re.IGNORECASE)
            if m:
                v = m.group(1).strip()
                if v and v.upper() not in _GENERIC_TYPES and len(v) >= 3:
                    return v.split(',')[0].strip()

        m = re.search(r'(?:^|\n)\s*malware\s*=\s*"([^"]{4,})"', meta_block, re.IGNORECASE | re.MULTILINE)
        if m:
            v = m.group(1).strip()
            if v.upper() not in _GENERIC_TYPES and len(v) >= 4:
                return v.split(',')[0].strip()

        return ''

    def _extract_from_rule_name(self, yara_text: str) -> str:
        """
        Parse les noms de règle YARA structurés.
        Ex: apt_apt28_drovorub → FancyBear
            crime_cobalt_gang_pdf → CobaltGroup
            mal_lockbit4_packed → LockBit
            Hidden_Cobra_DPRK_DDoS → HiddenCobra
        """
        rule_match = re.search(r'rule\s+(\w+)', yara_text)
        if not rule_match:
            return ''

        rule_name = rule_match.group(1).lower()
        return self._parse_name_tokens(rule_name)

    def _extract_from_filename_family(self, filename: str) -> str:
        """
        Extrait la famille depuis le nom de fichier.
        Ex: apt_apt28_drovorub.yar → FancyBear
            WannaCry_detection.yar → WannaCry
        """
        name = re.sub(r'\.(yar|yara|rule|txt)$', '', filename, flags=re.IGNORECASE)
        name_lower = name.lower()
        return self._parse_name_tokens(name_lower)

    def _parse_name_tokens(self, name: str) -> str:
        """v4: min 5 chars, blacklist élargie pour éviter Play/Hive/Storm sur des noms courants."""
        _COMMON_WORDS = {
            'Identifies', 'Detects', 'Detection', 'Unknown', 'Malware', 'Windows',
            'Linux', 'MacOS', 'Android', 'Network', 'Memory', 'Process', 'System',
            'Service', 'Module', 'Driver', 'Library', 'Microsoft', 'Adobe',
            'Hidden', 'Autumn', 'Winter', 'Spring', 'Summer', 'Alpha', 'Beta',
            'Delta', 'Sigma', 'Office', 'Server', 'Client', 'Agent', 'Config',
            'Install', 'Loader', 'Dropper', 'Packer', 'Static', 'Debug',
            'Index', 'Plugin', 'Script', 'Compiled', 'Signed', 'Packed',
            'Encoded', 'Obfuscated', 'Campaign', 'Report', 'Analysis', 'Generic',
        }
        for key, family in _APT_FAMILY_MAP.items():
            if key in name:
                return family
        name_clean = name.replace('_', ' ').replace('-', ' ')
        for family in self.known_families:
            if family.lower() in name_clean:
                return family
        tokens = re.split(r'[_\-\s]+', name)
        for token in tokens:
            if (len(token) >= 5
                    and token[0].isupper()
                    and token not in _COMMON_WORDS
                    and token not in _FAMILY_BLACKLIST
                    and token.lower() not in {
                        'apt', 'mal', 'gen', 'susp', 'expl', 'crime', 'yara',
                        'rule', 'win', 'linux', 'mac', 'elf', 'doc', 'pdf',
                        'rtf', 'xls', 'vba', 'net', 'pdb', 'path', 'file',
                        'code', 'index', 'test', 'unk', 'temp', 'stage',
                    }):
                return token.title() if token.islower() else token
        return ''

    def extract_malware_type(self, text: str,
                              filename: str = '',
                              yara_text: str = '') -> str:
        """
        Stratégie en cascade :
        1. Depuis le nom de fichier (préfixe structuré)
        2. Depuis le nom de la règle YARA
        3. Depuis le texte (keyword scoring)
        """
        # 1. Depuis le nom de fichier
        if filename:
            mtype = self._type_from_filename(filename)
            if mtype:
                return mtype

        # 2. Depuis le nom de la règle
        if yara_text:
            rule_match = re.search(r'rule\s+(\w+)', yara_text)
            if rule_match:
                mtype = self._type_from_filename(rule_match.group(1))
                if mtype:
                    return mtype

        # 3. Keyword scoring dans le texte
        text_lower = text.lower()
        scores: Dict[str, int] = {}
        for mtype, keywords in self.malware_types.items():
            score = sum(1 for kw in keywords if kw in text_lower)
            if score > 0:
                scores[mtype] = score
        if scores:
            return max(scores, key=scores.get)

        return "unknown"

    def _type_from_filename(self, name: str) -> str:
        """Déduit le type depuis un nom de fichier ou de règle."""
        name_lower = name.lower().replace('-', '_')
        # Chercher les préfixes dans l'ordre (les plus spécifiques d'abord)
        for prefix, mtype in sorted(_FILENAME_TYPE_MAP.items(), key=lambda x: -len(x[0])):
            if prefix in name_lower:
                return mtype
        return ''

    # ─────────────────────────────────────────────
    # EXTRACTION IOCs
    # ─────────────────────────────────────────────
    def extract_iocs(self, text: str) -> List[str]:
        iocs = []
        for ioc_type, pattern in self.ioc_patterns.items():
            try:
                if ioc_type == 'mutex':
                    matches = re.findall(pattern, text, re.IGNORECASE)
                else:
                    matches = re.findall(pattern, text)
                filtered = self._filter_ioc_false_positives(matches, ioc_type)
                iocs.extend(filtered)
            except re.error:
                continue
        return list(dict.fromkeys(iocs))

    def _filter_ioc_false_positives(self, matches: List[str], ioc_type: str) -> List[str]:
        filtered = []
        for match in matches:
            if not match or len(match) < 3:
                continue

            if ioc_type == 'ip':
                if any(match.startswith(net) for net in _LOOPBACK_NETS):
                    continue
                parts = match.split('.')
                try:
                    if not all(0 <= int(p) <= 255 for p in parts):
                        continue
                except ValueError:
                    continue
                filtered.append(match)

            elif ioc_type == 'domain':
                lower = match.lower()
                if len(match) < 6:
                    continue
                if any(lower.endswith(ext) for ext in _FILE_EXTENSIONS):
                    continue
                base = lower.split('.')[0]
                if base in _DOMAIN_FALSE_POSITIVES:
                    continue
                # FIX v3: normaliser ww. → www. (artefact PDF)
                if match.startswith('ww.') and not match.startswith('www.'):
                    match = 'www.' + match[3:]
                filtered.append(match)

            elif ioc_type in ('hash_md5', 'hash_sha1', 'hash_sha256'):
                if len(set(match)) <= 2:
                    continue
                filtered.append(match)

            elif ioc_type == 'win_path':
                if len(match) < 10:
                    continue
                filtered.append(match)

            else:
                filtered.append(match)

        return filtered

    # ─────────────────────────────────────────────
    # EXTRACTION COMPORTEMENTS
    # ─────────────────────────────────────────────
    def extract_behaviors(self, text: str) -> List[str]:
        text_lower = text.lower()
        behaviors = []

        behavior_keywords = {
            'file encryption': ['encrypt file', 'encrypted file', 'aes-', 'rsa encrypt', 'cipher', 'ransom'],
            'shadow copy deletion': ['vssadmin', 'shadow copy', 'delete shadow', 'wbadmin delete'],
            'registry modification': ['reg add', 'regedit', 'registry run key', 'hkey_'],
            'persistence via scheduled task': ['schtasks', 'scheduled task', 'at.exe', 'taskschd'],
            'process injection': ['process injection', 'process hollow', 'apc inject', 'dll inject', 'reflective'],
            'shellcode execution': ['shellcode', 'shellcode loader', 'shellcode payload', 'exec shellcode'],
            'network communication': ['command and control', 'c2 ', 'beacon', 'dns query', 'https c2', 'icmp c2'],
            'anti-analysis': ['vm check', 'sandbox detect', 'debugger detect', 'anti-forensic', 'syslog suppress'],
            'data exfiltration': ['exfiltrate', 'upload data', 'ftp transfer', 'dns tunnel', 'icmp exfil'],
            'lateral movement': ['psexec', 'wmiexec', 'smbexec', 'pass the hash', 'lateral'],
            'credential harvesting': ['lsass', 'mimikatz', 'credential dump', 'password harvest', 'token steal'],
            'bootkit/rootkit activity': ['bootkit', 'grub hook', 'uefi', 'kernel hook', 'driver load'],
            'anti-forensics': ['anti-forensic', 'core dump block', 'log wipe', 'syslog tamper', 'memory wipe'],
        }

        for behavior, keywords in behavior_keywords.items():
            if any(kw in text_lower for kw in keywords):
                behaviors.append(behavior)

        return behaviors

    # ─────────────────────────────────────────────
    # EXTRACTION ATTACK STAGE
    # ─────────────────────────────────────────────
    def extract_attack_stage(self, text: str) -> str:
        text_lower = text.lower()
        scores: Dict[str, int] = {}
        for stage, keywords in self.attack_stages.items():
            score = sum(1 for kw in keywords if kw in text_lower)
            if score > 0:
                scores[stage] = score
        if scores:
            return max(scores, key=scores.get)
        return "unknown"

    # ─────────────────────────────────────────────
    # EXTRACTION RÈGLES YARA
    # ─────────────────────────────────────────────
    def extract_yara_rules(self, text: str) -> List[str]:
        pattern = r'rule\s+\w+(?:\s*:\s*[\w\s]+)?\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\}'
        matches = re.findall(pattern, text, re.DOTALL)
        return [m.strip() for m in matches if len(m) > 50]

    def extract_yara_rule(self, text: str) -> Optional[str]:
        rules = self.extract_yara_rules(text)
        return rules[0] if rules else None

    def extract_rule_conditions(self, rule_text: str) -> List[str]:
        conditions = []
        condition_keywords = [
            'filesize', 'uint16', 'uint32', 'uint8', 'entropy',
            'pe.imphash', 'pe.sections', 'math.entropy',
            'for any', 'all of', 'any of', 'none of',
            '3 of them', '2 of them',
        ]
        rule_lower = rule_text.lower()
        for kw in condition_keywords:
            if kw in rule_lower:
                conditions.append(kw)
        return conditions

    def extract_strings_patterns(self, text: str) -> List[str]:
        """v4: exclure les métadonnées YARA (creation_date, author, etc.) des patterns."""
        _META_FIELDS = {
            'id', 'fingerprint', 'version', 'date', 'modified', 'status',
            'sharing', 'source', 'author', 'description', 'category',
            'malware', 'reference', 'hash', 'creation_date', 'first_imported',
            'last_modified', 'malware_type', 'malware_family', 'mitre_att',
        }
        patterns = []
        yara_strings = re.findall(r'"([^"]{4,})"', text)
        for s in yara_strings:
            s_stripped = s.strip()
            # Exclure les fragments de métadonnées
            if not s_stripped or s_stripped.startswith(('\n', '\t')):
                continue
            # "creation_date = " ou "author = " → champ meta
            first_word = s_stripped.split()[0].rstrip('=').lower() if s_stripped.split() else ''
            if first_word in _META_FIELDS:
                continue
            # Pattern comme " \n author = " (whitespace + field)
            if re.match(r'^\s*[a-z_]+\s*=\s*$', s_stripped):
                continue
            if len(s_stripped.split()) <= 8:
                patterns.append(s_stripped)

        hex_patterns = re.findall(r'\{([0-9A-Fa-f\s]{12,})\}', text)
        patterns.extend(f'hex:{h.strip()[:40]}' for h in hex_patterns[:5])
        return list(dict.fromkeys(patterns))[:20]

    def _is_likely_legit_tool(self, text: str) -> bool:
        """
        v4: détecte si le texte décrit un outil légitime de protection/obfuscation.
        Utilisé pour éviter de classer DotNet_Reactor, Enigma, AutoIT comme ransomware.
        """
        text_lower = text.lower()
        legit_indicators = [
            '.net code protection', 'obfuscation tool', 'code protection',
            'dotnet reactor', 'net reactor', 'eziriz', 'enigma protector',
            'costura', 'protobuf', 'compiled autoit', 'autoit script',
            'this rule by itself does not', 'not necessarily mean',
            'generic phishing', 'office 365 phishing', 'test vm',
            'ieuser', 'grimresource', 'iso exec', 'udf image',
        ]
        return any(ind in text_lower for ind in legit_indicators)

    def extract_best_sentences(self, text: str, n: int = 2) -> str:
        cyber_keywords = {
            'malware', 'ransomware', 'trojan', 'backdoor', 'rootkit', 'bootkit',
            'exploit', 'vulnerability', 'attack', 'threat', 'infection', 'payload',
            'encrypt', 'decrypt', 'c2', 'command', 'control', 'exfiltrate',
            'persist', 'privilege', 'lateral', 'credential', 'shellcode',
            'yara', 'ioc', 'indicator', 'detection', 'signature', 'hash',
            'apt', 'actor', 'campaign', 'operation', 'threat group',
        }

        sentences = re.split(r'(?<=[.!?])\s+', text)
        sentences = [s.strip() for s in sentences if 20 < len(s.strip()) < 400]

        scored = []
        for s in sentences:
            s_lower = s.lower()
            score = sum(1 for kw in cyber_keywords if kw in s_lower)
            for family in self.known_families:
                if family.lower() in s_lower:
                    score += 3
            scored.append((score, s))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = [s for _, s in scored[:n] if _ > 0]

        if top:
            return ' '.join(top)
        non_toc = [s for s in sentences if not re.match(r'^\d+[\.\)]\s*\w', s)]
        return ' '.join(non_toc[:n]) if non_toc else (sentences[0] if sentences else '')
    
    def extract_family_from_source_filename(self, filename: str) -> str:
        """
        Extrait la famille depuis le nom du fichier .yar/.yara.
        Ex: 'malware_macos_apt_sofacy_xagent.yara' → 'FancyBear'
        Ex: 'RokRAT.yar' → 'RokRAT'
        Ex: 'apt_careto_generic.yar' → 'Careto'
        """
        # Normaliser
        name = filename.lower()
        name = re.sub(r'\.(yar|yara|rule)$', '', name)
        name = re.sub(r'[_\-\.]+', ' ', name)
        
        # Vérifier chaque famille connue
        for family in self.known_families:
            if family.lower() in name:
                return family
        
        # Vérifier le mapping APT
        for key, value in _APT_FAMILY_MAP.items():
            if key in name:
                return value
        
        return 'unknown'