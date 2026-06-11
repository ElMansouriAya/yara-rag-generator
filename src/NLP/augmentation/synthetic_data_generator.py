#!/usr/bin/env python3
"""
==================================================
SYNTHETIC DATA GENERATOR — NLP Pipeline 
==================================================
Génère des données synthétiques pour enrichir le dataset.

4 stratégies :
  1. Variation sémantique     — paraphrase description + embedding
  2. Combinaison cross-famille — fusionner comportements de 2 familles
  3. Augmentation comportements — nouveaux scénarios MITRE ATT&CK
  4. Templates famille connue  — records complets pour familles manquantes

Placement : src/augmentation/synthetic_data_generator.py
Usage     : python synthetic_data_generator.py
==================================================
"""

import json
import re
import random
import hashlib
from copy import deepcopy
from pathlib import Path
from typing import List, Dict, Optional
from collections import Counter


# ─────────────────────────────────────────────────────────────
# DONNÉES DE RÉFÉRENCE CYBERSÉCURITÉ
# ─────────────────────────────────────────────────────────────

# Synonymes pour la variation sémantique des descriptions
BEHAVIOR_SYNONYMS = {
    "file encryption":              ["encrypts victim files", "AES file locking", "ransomware encryption routine"],
    "shadow copy deletion":         ["deletes VSS snapshots", "wipes volume shadow copies", "removes backup shadows"],
    "process injection":            ["injects into running processes", "DLL hollowing technique", "remote thread injection"],
    "credential harvesting":        ["dumps LSASS credentials", "steals authentication tokens", "extracts saved passwords"],
    "network communication":        ["beacons to C2 server", "establishes command channel", "sends heartbeat to C&C"],
    "data exfiltration":            ["exfiltrates sensitive data", "uploads stolen files via FTP", "tunnels data over DNS"],
    "lateral movement":             ["moves laterally via SMB", "uses PsExec for propagation", "spreads through network shares"],
    "persistence via scheduled task": ["installs scheduled task", "adds registry run key", "creates startup service"],
    "shellcode execution":          ["executes injected shellcode", "runs position-independent code", "reflective PE loading"],
    "anti-analysis":                ["detects virtual machine", "evades sandbox detection", "checks for debugger presence"],
    "anti-forensics":               ["clears event logs", "wipes forensic artifacts", "tampers with audit trails"],
    "bootkit/rootkit activity":     ["hooks kernel functions", "modifies boot sector", "installs UEFI implant"],
    "registry modification":        ["modifies HKLM run keys", "adds persistence registry entry", "alters system registry"],
}

# Templates de descriptions par type de malware
DESCRIPTION_TEMPLATES = {
    "ransomware": [
        "{family} ransomware that encrypts victim files using {algo} and demands {currency} payment.",
        "{family} encrypts files with {algo}, appends {ext} extension, drops ransom note demanding {currency}.",
        "Ransomware variant {family} targeting {target} systems, uses {algo} encryption and {evasion} evasion.",
    ],
    "trojan": [
        "{family} remote access trojan providing full backdoor access to compromised systems.",
        "{family} RAT with {features} capabilities, communicates with C2 over {protocol}.",
        "Modular trojan {family} used in {campaign} campaigns for credential theft and lateral movement.",
    ],
    "spyware": [
        "{family} infostealer targeting browser credentials, cryptocurrency wallets, and clipboard data.",
        "{family} keylogger and credential harvester deployed via {vector} phishing campaigns.",
        "Spyware {family} exfiltrates sensitive data including passwords, cookies, and {target} data.",
    ],
    "exploit": [
        "{family} exploit targeting {cve} vulnerability in {software} for remote code execution.",
        "Exploit kit {family} delivering {payload} via drive-by download targeting {browser} users.",
        "{family} leverages {cve} in {software} to achieve {impact} on unpatched systems.",
    ],
    "loader": [
        "{family} malware loader delivering {payload} as second-stage via encrypted {channel}.",
        "{family} first-stage loader using {technique} to bypass AV and download {payload}.",
        "Loader component {family} unpacks and executes {payload} in memory without touching disk.",
    ],
    "rootkit": [
        "{family} kernel-mode rootkit hiding malicious processes and network connections.",
        "{family} UEFI rootkit persisting across OS reinstallation on {target} hardware.",
        "Bootkit {family} infecting MBR/UEFI to load malicious kernel modules at boot time.",
    ],
}

# Paramètres de substitution pour les templates
TEMPLATE_PARAMS = {
    "algo":     ["AES-256", "ChaCha20", "Salsa20", "RSA-2048", "AES-128"],
    "currency": ["Bitcoin", "Monero", "Ethereum"],
    "ext":      [".locked", ".encrypted", ".enc", ".crypt", ".pay2decrypt"],
    "target":   ["Windows", "Linux", "enterprise", "healthcare", "critical infrastructure"],
    "evasion":  ["sandbox", "VM", "debugger", "antivirus"],
    "features": ["keylogging", "screenshot capture", "clipboard monitoring", "file browsing"],
    "protocol": ["HTTPS", "DNS-over-HTTPS", "custom TCP", "Tor"],
    "campaign": ["APT", "ransomware-as-a-service", "supply chain", "spear-phishing"],
    "vector":   ["email", "malicious macro", "drive-by", "watering hole"],
    "cve":      ["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708"],
    "software": ["Log4j", "Windows Print Spooler", "Exchange Server", "Apache", "IIS"],
    "browser":  ["Chrome", "Firefox", "Edge", "Internet Explorer"],
    "payload":  ["Cobalt Strike beacon", "Meterpreter", "ransomware", "RAT", "cryptominer"],
    "channel":  ["HTTPS", "DNS tunneling", "steganography", "cloud storage"],
    "technique": ["process hollowing", "reflective loading", "LOLBins", "AMSI bypass"],
    "impact":   ["remote code execution", "privilege escalation", "data exfiltration"],
}

# Familles bien connues avec leurs attributs pour la stratégie 4
FAMILY_TEMPLATES = {
    "WannaCry": {
        "malware_type": "ransomware",
        "behavior_summary": ["file encryption", "lateral movement", "shadow copy deletion", "network communication"],
        "attack_stage": "impact",
        "ioc": ["tasksche.exe", "mssecsvc.exe", "WANNACRY", "@Please_Read_Me@.txt"],
        "strings_or_patterns": ["WannaDecryptor", "tasksche.exe", "mssecsvc2.0", ".WNCRY"],
        "rule_conditions": ["filesize", "any of them"],
        "description": "WannaCry ransomworm exploiting EternalBlue (MS17-010) for lateral movement, encrypts files with AES-128 and RSA-2048.",
        "notes_on_fp": "May match EternalBlue scanner tools; check for ransomware strings",
    },
    "Emotet": {
        "malware_type": "trojan",
        "behavior_summary": ["network communication", "credential harvesting", "lateral movement", "persistence via scheduled task"],
        "attack_stage": "initial-access",
        "ioc": ["emotet.exe", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "strings_or_patterns": ["emotet", "spam module", "credential stealer", "outlook harvester"],
        "rule_conditions": ["filesize", "pe.imphash", "any of them"],
        "description": "Emotet modular banking trojan acting as dropper for TrickBot and Ryuk, spreads via malspam with malicious documents.",
        "notes_on_fp": "High FP rate on packed executables; use pe.imphash for precision",
    },
    "CobaltStrike": {
        "malware_type": "trojan",
        "behavior_summary": ["network communication", "process injection", "credential harvesting", "lateral movement", "shellcode execution"],
        "attack_stage": "command-and-control",
        "ioc": ["beacon.dll", "artifact.exe", "cobaltstrike"],
        "strings_or_patterns": ["beacon", "ReflectiveDll", "cobaltstrike", "Cobalt Strike"],
        "rule_conditions": ["pe.imphash", "any of them", "filesize"],
        "description": "Cobalt Strike commercial red-team framework widely abused by threat actors for C2, lateral movement, and privilege escalation.",
        "notes_on_fp": "Legitimate red team usage — correlate with threat intelligence before alerting",
    },
    "Mimikatz": {
        "malware_type": "trojan",
        "behavior_summary": ["credential harvesting", "process injection", "lateral movement"],
        "attack_stage": "credential-access",
        "ioc": ["mimikatz.exe", "mimilib.dll", "sekurlsa.dll"],
        "strings_or_patterns": ["mimikatz", "sekurlsa", "lsadump", "privilege::debug", "sekurlsa::logonpasswords"],
        "rule_conditions": ["any of them"],
        "description": "Mimikatz credential dumping tool extracting plaintext passwords, hashes, and Kerberos tickets from Windows LSASS memory.",
        "notes_on_fp": "Many variants exist; consider behavioral detection alongside static signatures",
    },
    "LockBit": {
        "malware_type": "ransomware",
        "behavior_summary": ["file encryption", "shadow copy deletion", "lateral movement", "data exfiltration", "anti-analysis"],
        "attack_stage": "impact",
        "ioc": [".lockbit", "Restore-My-Files.txt", "vssadmin delete shadows /all /quiet"],
        "strings_or_patterns": ["LockBit", ".lockbit", "Restore-My-Files.txt", "vssadmin"],
        "rule_conditions": ["filesize", "any of them", "entropy"],
        "description": "LockBit ransomware-as-a-service operation encrypting files with AES+RSA, spreading laterally via SMB and deleting shadow copies.",
        "notes_on_fp": "Entropy check alone may match legitimate packers; combine with string matching",
    },
    "Ryuk": {
        "malware_type": "ransomware",
        "behavior_summary": ["file encryption", "shadow copy deletion", "process injection", "lateral movement"],
        "attack_stage": "impact",
        "ioc": ["RyukReadMe.html", "RYUK", "hermes"],
        "strings_or_patterns": ["RYUK", "RyukReadMe.html", "No system is safe", "UNIQUE_ID_DO_NOT_REMOVE"],
        "rule_conditions": ["filesize", "any of them"],
        "description": "Ryuk ransomware targeting enterprise environments, typically deployed post-Emotet/TrickBot infection, encrypts with AES-256+RSA-4096.",
        "notes_on_fp": "Shares code with Hermes ransomware — check for both string sets",
    },
    "TrickBot": {
        "malware_type": "trojan",
        "behavior_summary": ["credential harvesting", "network communication", "lateral movement", "data exfiltration", "persistence via scheduled task"],
        "attack_stage": "collection",
        "ioc": ["trickbot.exe", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost"],
        "strings_or_patterns": ["TrickBot", "trickboot", "user_platform", "user_info"],
        "rule_conditions": ["pe.imphash", "any of them"],
        "description": "TrickBot modular banking trojan stealing credentials, browser data, and Active Directory information, often used to deploy Ryuk.",
        "notes_on_fp": "Module-based architecture — different detections needed per module",
    },
}

# Scénarios MITRE ATT&CK pour la stratégie 3
MITRE_SCENARIOS = [
    {
        "attack_stage": "initial-access",
        "behavior": "phishing with malicious macro",
        "behaviors": ["persistence via scheduled task", "network communication", "credential harvesting"],
        "strings": ["AutoOpen", "Shell", "WScript.Shell", "cmd.exe", "powershell"],
        "iocs": ["malicious.docm", "HKCU\\Software\\Microsoft\\Office\\"],
        "description_template": "Malicious {filetype} document using VBA macro to download and execute second-stage payload via {method}.",
        "params": {"filetype": ["Word", "Excel", "PowerPoint"], "method": ["PowerShell", "WScript", "cmd.exe"]},
    },
    {
        "attack_stage": "defense-evasion",
        "behavior": "process hollowing",
        "behaviors": ["process injection", "shellcode execution", "anti-analysis"],
        "strings": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"],
        "iocs": ["svchost.exe", "explorer.exe"],
        "description_template": "Process hollowing technique injecting malicious code into legitimate {process} process to evade detection.",
        "params": {"process": ["svchost.exe", "explorer.exe", "notepad.exe", "iexplore.exe"]},
    },
    {
        "attack_stage": "persistence",
        "behavior": "registry run key",
        "behaviors": ["registry modification", "persistence via scheduled task", "network communication"],
        "strings": ["HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "RegSetValueEx"],
        "iocs": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "description_template": "Malware establishing persistence via {method} to survive system reboots and maintain access.",
        "params": {"method": ["registry run keys", "scheduled tasks", "startup folder", "service installation"]},
    },
    {
        "attack_stage": "exfiltration",
        "behavior": "DNS tunneling exfiltration",
        "behaviors": ["data exfiltration", "network communication", "anti-forensics"],
        "strings": ["DnsQuery", "base64", "TXT record", "nslookup"],
        "iocs": ["dnscat2", "iodine", "dns2tcp"],
        "description_template": "Data exfiltration via {protocol} tunneling, encoding stolen data in {field} records to bypass DLP controls.",
        "params": {"protocol": ["DNS", "ICMP", "HTTP"], "field": ["TXT", "CNAME", "MX", "A"]},
    },
    {
        "attack_stage": "privilege-escalation",
        "behavior": "UAC bypass",
        "behaviors": ["process injection", "registry modification", "shellcode execution"],
        "strings": ["fodhelper.exe", "eventvwr.exe", "sdclt.exe", "DelegateExecute"],
        "iocs": ["HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command", "fodhelper.exe"],
        "description_template": "UAC bypass using {method} technique to elevate privileges without triggering UAC prompt.",
        "params": {"method": ["fodhelper", "eventvwr", "sdclt", "DiskCleanup", "CMSTPLUA"]},
    },
    {
        "attack_stage": "command-and-control",
        "behavior": "HTTPS C2 beaconing",
        "behaviors": ["network communication", "anti-analysis", "data exfiltration"],
        "strings": ["Mozilla/5.0", "Content-Type: application/json", "User-Agent", "beacon_interval"],
        "iocs": ["WinHttpOpen", "InternetOpenUrl", "HttpSendRequest"],
        "description_template": "C2 communication using {protocol} with {technique} to blend in with legitimate traffic and evade network detection.",
        "params": {"protocol": ["HTTPS", "HTTP/2", "WebSocket"], "technique": ["domain fronting", "malleable profile", "JA3 spoofing"]},
    },
]


# ─────────────────────────────────────────────────────────────
# GÉNÉRATEUR PRINCIPAL
# ─────────────────────────────────────────────────────────────

class SyntheticDataGenerator:
    """
    Génère des records synthétiques valides en respectant le schéma JSON.
    
    Principe : toutes les données générées sont dérivées de données
    cybersécurité réelles — pas d'hallucination, pas d'invention pure.
    """

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.counters: Dict[str, int] = {}
        self.existing_ids = set()
        self.existing_embeddings = set()

    def generate_all(self, source_records: List[Dict], target_count: int = 500) -> List[Dict]:
        """
        Point d'entrée principal. Génère jusqu'à target_count records synthétiques.
        """
        # Indexer les records existants
        self._index_existing(source_records)

        synthetic = []

        # Stratégie 1 : Variation sémantique (40% du quota)
        quota_s1 = int(target_count * 0.40)
        s1 = self._strategy1_semantic_variation(source_records, quota_s1)
        synthetic.extend(s1)
        print(f"  Stratégie 1 (variation sémantique)    : {len(s1)} records")

        # Stratégie 2 : Combinaison cross-famille (30% du quota)
        quota_s2 = int(target_count * 0.30)
        s2 = self._strategy2_cross_family(source_records, quota_s2)
        synthetic.extend(s2)
        print(f"  Stratégie 2 (combinaison cross-famille): {len(s2)} records")

        # Stratégie 3 : Scénarios MITRE ATT&CK (20% du quota)
        quota_s3 = int(target_count * 0.20)
        s3 = self._strategy3_mitre_scenarios(quota_s3)
        synthetic.extend(s3)
        print(f"  Stratégie 3 (scénarios MITRE ATT&CK)  : {len(s3)} records")

        # Stratégie 4 : Templates familles connues (10% du quota)
        quota_s4 = int(target_count * 0.10)
        s4 = self._strategy4_family_templates(quota_s4)
        synthetic.extend(s4)
        print(f"  Stratégie 4 (templates familles)       : {len(s4)} records")

        # Post-traitement : validation + déduplication
        validated = self._validate_and_deduplicate(synthetic)
        print(f"\n  Total généré   : {len(synthetic)}")
        print(f"  Après validation : {len(validated)} records valides")

        return validated

    def _index_existing(self, records: List[Dict]):
        """Indexe les records existants pour éviter les doublons."""
        for r in records:
            self.existing_ids.add(r.get('id', ''))
            emb = r.get('embedding_text', '')
            if emb:
                self.existing_embeddings.add(self._fingerprint(emb))

    # ─────────────────────────────────────────────────────────
    # STRATÉGIE 1 — Variation sémantique
    # ─────────────────────────────────────────────────────────

    def _strategy1_semantic_variation(self, records: List[Dict], count: int) -> List[Dict]:
        """
        Prend des records existants de haute qualité et génère des
        variations en reformulant description, behaviors et embedding_text.
        """
        # Sélectionner les records high confidence avec famille connue
        candidates = [
            r for r in records
            if r.get('confidence') == 'high'
            and r.get('malware_family', 'unknown') != 'unknown'
            and r.get('behavior_summary')
            and len(r.get('description', '')) > 80
        ]

        if not candidates:
            return []

        synthetic = []
        for _ in range(count):
            base = deepcopy(random.choice(candidates))
            variant = self._create_semantic_variant(base)
            if variant:
                synthetic.append(variant)

        return synthetic

    def _create_semantic_variant(self, base: Dict) -> Optional[Dict]:
        """Crée une variation sémantique d'un record."""
        r = deepcopy(base)

        # Nouveau ID
        r['id'] = self._make_id(r.get('malware_type', 'unknown'))
        r['source_document'] = 'synthetic_variation'
        r['confidence'] = 'medium'  # Synthétique → confiance medium par défaut

        # Variation des comportements : garder 70-100% et reformuler
        behaviors = r.get('behavior_summary', [])
        if behaviors:
            keep_n = max(2, int(len(behaviors) * random.uniform(0.7, 1.0)))
            selected = random.sample(behaviors, min(keep_n, len(behaviors)))
            # Substituer certains comportements par des synonymes
            varied = []
            for b in selected:
                if b in BEHAVIOR_SYNONYMS and random.random() < 0.4:
                    varied.append(random.choice(BEHAVIOR_SYNONYMS[b]))
                else:
                    varied.append(b)
            r['behavior_summary'] = varied

        # Variation de la description (reformulation légère)
        desc = r.get('description', '')
        if desc:
            r['description'] = self._paraphrase_description(desc, r)

        # Re-générer l'embedding_text depuis les champs modifiés
        r['embedding_text'] = self._generate_embedding(r)

        # Marquer comme synthétique
        r['notes_on_fp'] = (r.get('notes_on_fp', '') + ' | synthetic:variation').strip(' |')

        return r if self._is_valid_synthetic(r) else None

    def _paraphrase_description(self, desc: str, record: Dict) -> str:
        """Reformule légèrement une description."""
        family = record.get('malware_family', '')
        mtype = record.get('malware_type', '')

        # Essayer un template si disponible
        if mtype in DESCRIPTION_TEMPLATES and family:
            template = random.choice(DESCRIPTION_TEMPLATES[mtype])
            try:
                params = {k: random.choice(v) for k, v in TEMPLATE_PARAMS.items()}
                params['family'] = family
                filled = template.format(**params)
                if len(filled) > 50:
                    return filled
            except (KeyError, IndexError):
                pass

        # Sinon retourner la description originale légèrement modifiée
        return desc

    # ─────────────────────────────────────────────────────────
    # STRATÉGIE 2 — Combinaison cross-famille
    # ─────────────────────────────────────────────────────────

    def _strategy2_cross_family(self, records: List[Dict], count: int) -> List[Dict]:
        """
        Combine les comportements de deux familles différentes pour simuler
        des malwares hybrides ou des dropper/payload scenarios.
        """
        # Grouper par famille
        by_family: Dict[str, List[Dict]] = {}
        for r in records:
            fam = r.get('malware_family', 'unknown')
            if fam != 'unknown' and r.get('confidence') in ('high', 'medium'):
                by_family.setdefault(fam, []).append(r)

        families = [f for f, rs in by_family.items() if len(rs) >= 1]
        if len(families) < 2:
            return []

        synthetic = []
        for _ in range(count):
            # Choisir deux familles différentes
            fam_a, fam_b = random.sample(families, 2)
            rec_a = random.choice(by_family[fam_a])
            rec_b = random.choice(by_family[fam_b])

            combined = self._combine_records(rec_a, rec_b)
            if combined:
                synthetic.append(combined)

        return synthetic

    def _combine_records(self, rec_a: Dict, rec_b: Dict) -> Optional[Dict]:
        """
        Combine deux records pour créer un scénario d'infection en chaîne.
        Ex: Emotet (dropper) + Ryuk (ransomware)
        """
        fam_a = rec_a.get('malware_family', 'FamilyA')
        fam_b = rec_b.get('malware_family', 'FamilyB')

        # Fusionner les comportements (union, sans doublons)
        behaviors_a = set(rec_a.get('behavior_summary', []))
        behaviors_b = set(rec_b.get('behavior_summary', []))
        combined_behaviors = list(behaviors_a | behaviors_b)[:8]  # max 8

        # Fusionner les IOCs (prendre les plus pertinents de chaque)
        iocs_a = rec_a.get('ioc', [])[:3]
        iocs_b = rec_b.get('ioc', [])[:3]
        combined_iocs = list(dict.fromkeys(iocs_a + iocs_b))

        # Choisir le type du record combiné
        # Si l'un est loader et l'autre ransomware → scenario dropper
        type_a = rec_a.get('malware_type', 'unknown')
        type_b = rec_b.get('malware_type', 'unknown')
        combined_type = type_b if type_a in ('loader', 'trojan') else type_a

        # Choisir l'attack_stage le plus avancé
        stage_priority = {
            'initial-access': 1, 'execution': 2, 'persistence': 3,
            'privilege-escalation': 4, 'defense-evasion': 5, 'credential-access': 6,
            'discovery': 7, 'lateral-movement': 8, 'collection': 9,
            'command-and-control': 10, 'exfiltration': 11, 'impact': 12, 'unknown': 0,
        }
        stage_a = rec_a.get('attack_stage', 'unknown')
        stage_b = rec_b.get('attack_stage', 'unknown')
        combined_stage = stage_a if stage_priority.get(stage_a, 0) > stage_priority.get(stage_b, 0) else stage_b

        description = (
            f"{fam_a} acting as initial loader delivering {fam_b} payload. "
            f"{fam_a} establishes persistence and lateral movement while "
            f"{fam_b} executes {combined_type} payload on target system."
        )

        r = {
            "id": self._make_id(combined_type),
            "description": description,
            "malware_family": fam_b,  # La famille principale = le payload final
            "malware_type": combined_type,
            "behavior_summary": combined_behaviors,
            "attack_stage": combined_stage,
            "ioc": combined_iocs,
            "yara_rule": rec_b.get('yara_rule', '') or rec_a.get('yara_rule', ''),
            "rule_conditions": rec_b.get('rule_conditions', []) or rec_a.get('rule_conditions', []),
            "strings_or_patterns": (rec_a.get('strings_or_patterns', [])[:3] +
                                    rec_b.get('strings_or_patterns', [])[:3]),
            "source_document": "synthetic_cross_family",
            "confidence": "medium",
            "notes_on_fp": f"Synthetic cross-family scenario: {fam_a} + {fam_b} | synthetic:combination",
            "language": "en",
            "embedding_text": "",
            "source_type": "synthetic",
        }
        r['embedding_text'] = self._generate_embedding(r)

        return r if self._is_valid_synthetic(r) else None

    # ─────────────────────────────────────────────────────────
    # STRATÉGIE 3 — Scénarios MITRE ATT&CK
    # ─────────────────────────────────────────────────────────

    def _strategy3_mitre_scenarios(self, count: int) -> List[Dict]:
        """
        Génère des records basés sur des techniques MITRE ATT&CK réelles.
        Ces records couvrent des TTPs génériques utiles pour le RAG.
        """
        synthetic = []
        scenarios_cycle = MITRE_SCENARIOS * (count // len(MITRE_SCENARIOS) + 1)

        for i in range(count):
            scenario = deepcopy(random.choice(MITRE_SCENARIOS))

            # Remplir le template de description
            params = {k: random.choice(v) for k, v in scenario.get('params', {}).items()}
            try:
                description = scenario['description_template'].format(**params)
            except (KeyError, IndexError):
                description = f"Malware technique: {scenario['behavior']}"

            r = {
                "id": self._make_id("trojan"),
                "description": description,
                "malware_family": "unknown",
                "malware_type": "trojan",
                "behavior_summary": [scenario['behavior']] + scenario['behaviors'],
                "attack_stage": scenario['attack_stage'],
                "ioc": scenario['iocs'],
                "yara_rule": self._generate_simple_yara(scenario['strings'], description),
                "rule_conditions": ["any of them"],
                "strings_or_patterns": scenario['strings'],
                "source_document": "synthetic_mitre_attck",
                "confidence": "medium",
                "notes_on_fp": f"Synthetic MITRE ATT&CK scenario: {scenario['attack_stage']} | synthetic:mitre",
                "language": "en",
                "embedding_text": "",
                "source_type": "synthetic",
            }
            r['embedding_text'] = self._generate_embedding(r)
            synthetic.append(r)

        return [r for r in synthetic if self._is_valid_synthetic(r)]

    def _generate_simple_yara(self, strings: List[str], description: str) -> str:
        """Génère une règle YARA simple depuis une liste de strings."""
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_',
                           description.split('.')[0][:40].replace(' ', '_'))
        rule_name = re.sub(r'_+', '_', rule_name).strip('_')

        strings_block = ""
        for i, s in enumerate(strings[:6]):
            clean_s = s.replace('"', '\\"').replace('\n', '\\n')
            strings_block += f'        $s{i} = "{clean_s}" ascii wide nocase\n'

        return f'''rule {rule_name} {{
    meta:
        description = "{description[:120]}"
        source = "synthetic_mitre_attck"
        confidence = "medium"
    strings:
{strings_block}
    condition:
        any of them
}}'''

    # ─────────────────────────────────────────────────────────
    # STRATÉGIE 4 — Templates familles connues
    # ─────────────────────────────────────────────────────────

    def _strategy4_family_templates(self, count: int) -> List[Dict]:
        """
        Génère des records complets pour des familles bien documentées
        mais sous-représentées dans le dataset.
        """
        families = list(FAMILY_TEMPLATES.keys())
        synthetic = []
        per_family = max(1, count // len(families))

        for family, attrs in FAMILY_TEMPLATES.items():
            for variant_idx in range(per_family):
                r = self._create_family_record(family, attrs, variant_idx)
                if r:
                    synthetic.append(r)

        return synthetic[:count]

    def _create_family_record(self, family: str, attrs: Dict, variant: int) -> Optional[Dict]:
        """Crée un record complet pour une famille connue."""
        mtype = attrs['malware_type']

        # Variation légère selon le variant
        behaviors = list(attrs['behavior_summary'])
        if variant > 0 and len(behaviors) > 2:
            behaviors = random.sample(behaviors, len(behaviors) - 1)

        # Générer une règle YARA simple
        strings = attrs.get('strings_or_patterns', [])
        rule_name = f"{family}_detection_v{variant + 1}"
        strings_block = ""
        for i, s in enumerate(strings[:6]):
            clean_s = s.replace('"', '\\"')
            strings_block += f'        $s{i} = "{clean_s}" ascii wide\n'

        yara_rule = f'''rule {rule_name} {{
    meta:
        description = "Detects {family} {mtype}"
        malware_family = "{family}"
        source = "synthetic_template"
        confidence = "high"
    strings:
{strings_block}
    condition:
        any of them
}}'''

        r = {
            "id": self._make_id(mtype),
            "description": self._vary_family_description(family, attrs, variant),
            "malware_family": family,
            "malware_type": mtype,
            "behavior_summary": behaviors,
            "attack_stage": attrs['attack_stage'],
            "ioc": attrs['ioc'],
            "yara_rule": yara_rule,
            "rule_conditions": attrs['rule_conditions'],
            "strings_or_patterns": strings,
            "source_document": f"synthetic_template_{family.lower()}",
            "confidence": "high",
            "notes_on_fp": attrs.get('notes_on_fp', '') + ' | synthetic:template',
            "language": "en",
            "embedding_text": "",
            "source_type": "synthetic",
        }
        r['embedding_text'] = self._generate_embedding(r)

        return r if self._is_valid_synthetic(r) else None

    def _vary_family_description(self, family, attrs, variant):
        templates = DESCRIPTION_TEMPLATES.get(attrs['malware_type'], [])
        if templates and variant > 0:
            tpl = templates[variant % len(templates)]
            params = {k: random.choice(v) for k, v in TEMPLATE_PARAMS.items()}
            params['family'] = family
            try:
                return tpl.format(**params)
            except KeyError:
                pass
        return attrs['description']


    # ─────────────────────────────────────────────────────────
    # UTILITAIRES
    # ─────────────────────────────────────────────────────────

    def _make_id(self, malware_type: str) -> str:
        """Génère un ID unique avec préfixe SYN pour distinguer les synthétiques."""
        prefix_map = {
            'ransomware': 'SYN-RAN', 'trojan': 'SYN-TRJ', 'rootkit': 'SYN-RTK',
            'spyware': 'SYN-SPY', 'worm': 'SYN-WRM', 'loader': 'SYN-LDR',
            'exploit': 'SYN-EXP', 'banker': 'SYN-BNK', 'miner': 'SYN-MIN',
            'generic': 'SYN-GEN', 'unknown': 'SYN-REC',
        }
        prefix = prefix_map.get(malware_type, 'SYN-REC')
        self.counters[prefix] = self.counters.get(prefix, 0) + 1
        return f"{prefix}-{self.counters[prefix]:03d}"

    def _generate_embedding(self, record: Dict) -> str:
        """Re-génère l'embedding_text depuis les champs du record."""
        parts = []

        desc = record.get('description', '')
        if desc and len(desc) > 20:
            parts.append(desc[:200])

        family = record.get('malware_family', 'unknown')
        if family != 'unknown':
            parts.extend([family, family])  # ×2 pour le poids

        mtype = record.get('malware_type', 'unknown')
        if mtype not in ('unknown', '', 'generic'):
            parts.append(mtype)

        behaviors = record.get('behavior_summary', [])
        parts.extend(str(b) for b in behaviors[:5])

        stage = record.get('attack_stage', '')
        if stage and stage != 'unknown':
            parts.append(stage)

        iocs = record.get('ioc', [])
        parts.extend(str(ioc) for ioc in iocs[:5] if len(str(ioc)) > 5)

        patterns = record.get('strings_or_patterns', [])
        meaningful = [p for p in patterns if isinstance(p, str) and len(p) > 4
                      and not p.startswith('hex:') and len(re.findall(r'[A-Za-z]', p)) >= 3]
        parts.extend(meaningful[:4])

        # Déduplication
        seen = set()
        unique = []
        for p in parts:
            p_norm = str(p).lower().strip()
            if p_norm and p_norm not in seen:
                seen.add(p_norm)
                unique.append(str(p))

        result = re.sub(r'\s+', ' ', ' '.join(unique)).lower().strip()
        return result

    def _fingerprint(self, text: str) -> str:
        """Crée une empreinte d'un texte pour la déduplication."""
        normalized = re.sub(r'\s+', ' ', text.lower().strip())
        return hashlib.md5(normalized.encode()).hexdigest()[:16]

    def _is_valid_synthetic(self, record: Dict) -> bool:
        """Valide qu'un record synthétique est utilisable."""
        embedding = record.get('embedding_text', '')

        if len(embedding) < 80:
            return False

        # Vérifier que ce n'est pas un doublon
        fp = self._fingerprint(embedding)
        if fp in self.existing_embeddings:
            return False
        self.existing_embeddings.add(fp)

        if not record.get('behavior_summary'):
            return False

        return True

    def _validate_and_deduplicate(self, records: List[Dict]) -> List[Dict]:
        """Validation finale et déduplication stricte."""
        seen_ids = set()
        valid = []

        for r in records:
            rid = r.get('id', '')
            if rid in seen_ids:
                # Générer un nouvel ID si collision
                r['id'] = r['id'] + f"-{len(valid):03d}"
            seen_ids.add(r.get('id', ''))

            # Vérifier les champs obligatoires du schéma
            required = ['id', 'description', 'malware_type', 'embedding_text',
                        'behavior_summary', 'language']
            if all(r.get(f) for f in required):
                valid.append(r)

        return valid


# ─────────────────────────────────────────────────────────────
# RAPPORT
# ─────────────────────────────────────────────────────────────

def print_augmentation_report(original: List[Dict], synthetic: List[Dict]):
    """Affiche le rapport d'augmentation."""
    total_orig = len(original)
    total_syn  = len(synthetic)
    total_new  = total_orig + total_syn

    print(f"\n{'='*60}")
    print(f"📊 RAPPORT D'AUGMENTATION")
    print(f"{'='*60}")
    print(f"  Records originaux   : {total_orig}")
    print(f"  Records synthétiques: {total_syn}")
    print(f"  Dataset enrichi     : {total_new} (+{total_syn/total_orig*100:.1f}%)")

    # Distribution par source synthétique
    sources = Counter(r.get('source_document', '') for r in synthetic)
    print(f"\n  Distribution synthétique :")
    for src, count in sources.most_common():
        print(f"    {src:40} : {count}")

    # Distribution familles dans les synthétiques
    fams = Counter(r.get('malware_family', 'unknown') for r in synthetic)
    print(f"\n  Familles dans les synthétiques (top 10) :")
    for fam, count in fams.most_common(10):
        print(f"    {fam:25} : {count}")

    # Confiance
    confs = Counter(r.get('confidence', '') for r in synthetic)
    print(f"\n  Confiance des synthétiques :")
    for c, n in confs.most_common():
        print(f"    {c:10} : {n}")

    print(f"\n{'='*60}")


# ─────────────────────────────────────────────────────────────
# POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────

def main():
    input_path  = Path("data/processed/filtered/dataset_production.json")
    output_path = Path("data/processed/filtered/dataset_production_enriched.json")

    if not input_path.exists():
        print(f"❌ Fichier introuvable : {input_path}")
        print("   Exécutez d'abord : python src/validation/data_quality_filter.py")
        import sys; sys.exit(1)

    print("=" * 60)
    print("🔬 SYNTHETIC DATA GENERATOR — NLP Pipeline")
    print("=" * 60)

    # Charger le dataset de production
    with open(input_path, 'r', encoding='utf-8') as f:
        original_records = json.load(f)

    print(f"  {len(original_records)} records chargés depuis {input_path}")
    print(f"\n  Génération en cours...")

    # Générer les données synthétiques
    generator = SyntheticDataGenerator(seed=42)
    synthetic_records = generator.generate_all(original_records, target_count=500)

    # Rapport
    print_augmentation_report(original_records, synthetic_records)

    # Fusionner et sauvegarder
    enriched = original_records + synthetic_records
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)

    size_kb = output_path.stat().st_size / 1024
    print(f"\n💾 Dataset enrichi sauvegardé :")
    print(f"   {output_path}")
    print(f"   {len(enriched)} records | {size_kb:.0f} Ko")
    print(f"\n✅ Livrez dataset_production_enriched.json à l'équipe RAG !")


if __name__ == "__main__":
    main()