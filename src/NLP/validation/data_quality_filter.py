#!/usr/bin/env python3
"""
==================================================
DATA QUALITY FILTER — NLP Pipeline v1
==================================================
Post-processing script that automatically filters and corrects
the knowledge_base.json produced by run_preprocessing.py.

Placement : src/validation/data_quality_filter.py
Usage     : python data_quality_filter.py
==================================================
"""

import json
import re
import sys
from pathlib import Path
from collections import Counter
from typing import List, Dict, Optional, Tuple


# ─────────────────────────────────────────────────────────────
# CONFIGURATION — Ajustez ces seuils selon votre dataset
# ─────────────────────────────────────────────────────────────

# Seuils de qualité minimaux pour conserver un record
MIN_EMBEDDING_LENGTH   = 80    # chars minimum dans embedding_text
MIN_DESCRIPTION_LENGTH = 30    # chars minimum dans description
MAX_IOC_COUNT          = 50    # au-delà c'est du bruit (ex: TRJ-002 avec 264)
MIN_IOC_MEANINGFUL     = 1     # un seul IOC réel suffit

# Domaines d'outils légitimes à exclure des IOCs
LEGITIMATE_TOOL_DOMAINS = {
    "dependencywalker.com", "angusj.com", "heaventools.com", "hex-rays.com",
    "ollydbg.de", "ida-pro.com", "x-ways.net", "sleuthkit.org",
    "wireshark.org", "sysinternals.com", "www.sysinternals.com",
    "sandboxie.com", "vmware.com", "virtualbox.org",
    "virustotal.com", "hybrid-analysis.com", "any.run",
    "cuckoo.cert.ee", "joesandbox.com", "joesecurity.org",
    "fireeye.com", "mandiant.com", "www.mandiant.com",
    "misp-project.org", "mitre.org", "attack.mitre.org",
    "snort.org", "emergingthreats.net", "doc.emergingthreats.net",
    "immunityinc.com", "metasploit.com", "portswigger.net",
    "inetsim.org", "torproject.org", "honeynet.org",
    "nirsoft.net", "domaintools.com", "robtex.com",
    "threatexpert.com", "secureworks.com", "www.secureworks.com",
    "offensivecomputing.net", "reconstructer.org", "ntcore.com",
    "osronline.com", "woodmann.com", "didierstevens.com",
    "ntinternals.net", "openrce.org", "tuts4you.com",
    "smidgeonsoft.prohosting.com", "zynamics.com", "www.zynamics.com",
    "mindviewinc.com", "trapkit.de", "smokedchicken.org",
    "faronics.com", "idefense.com", "malwareanalysisbok.com",
    "whatismyipaddress.com", "bfk.de", "wjradburn.com",
    "nationalarchives.gov.uk",   # source NCSC légitime (pas un IOC)
    "ncsc.gov.uk",               # source légitime
    "ncscinfoleg@ncsc.gov.uk",   # email de contact officiel
    "flaticon.com", "w3.org", "eff.org", "github.com",
    "python.org", "openssl.org", "intel.com", "oracle.com",
    "adobe.com", "microsoft.com", "google.com", "yahoo.com",
    "wikipedia.org", "example.com", "vmware.com", "sourceforge.net",
}

# Familles malware reconnues (liste étendue)
KNOWN_MALWARE_FAMILIES = {
    # Ransomware
    "LockBit", "Ryuk", "Conti", "REvil", "DarkSide", "WannaCry",
    "Petya", "NotPetya", "Cerber", "CryptoLocker", "BlackMatter",
    "Hive", "BlackCat", "Clop", "Maze", "Sodinokibi", "GandCrab",
    "Dharma", "Phobos", "Locky", "CryptoWall", "TeslaCrypt",
    "Royal", "Play", "Cuba", "Ragnar", "MedusaLocker", "Babuk",
    "Avaddon", "Grief", "Prometheus", "BlackSuit", "Akira",
    # Trojans / RATs / Backdoors
    "Emotet", "TrickBot", "Dridex", "Qakbot", "IcedID",
    "AgentTesla", "FormBook", "Remcos", "AsyncRAT", "NjRAT",
    "QuasarRAT", "DarkComet", "PoisonIvy", "PlugX", "Gh0stRAT",
    "CobaltStrike", "Mimikatz", "BloodHound", "NetWire",
    "BitRAT", "XWorm", "Warzone", "NanoCore",
    "Backdoor", "Comment_Crew", "Turla", "FancyBear", "CozyBear",
    # APT / Nation-State
    "RayInitiator", "LineViper", "Stuxnet", "Duqu", "Flame", "Regin",
    "BlackEnergy", "GreyEnergy", "Industroyer", "Triton",
    "Lazarus", "Carbanak", "FIN7", "FIN6", "OceanLotus",
    "SideWinder", "MuddyWater", "Gamaredon", "HiddenCobra",
    "DarkHotel", "OilRig", "Sandworm", "Gothic_Panda",
    "Winnti", "LuckyMouse", "EquationGroup", "Ghostwriter",
    "BlackHole", "Buhtrap", "LotusBlossom", "MenuPass",
    # Worms / Bots
    "Conficker", "Mirai", "Mariposa", "Storm", "ZeroAccess",
    # Stealers / Spyware
    "RedLine", "Raccoon", "Vidar", "AZORult", "Lumma", "Phemedrone",
    # Loaders
    "GuLoader", "DBatLoader", "SmokeLoader", "PrivateLoader",
    # Tools détectés en YARA
    "NSPPS", "Gazer", "ComRAT", "REIGN", "Coathanger",
    "BabbleLoader", "XLogin",
}

# Textes de description inutiles (table des matières, listes)
USELESS_DESCRIPTION_PATTERNS = [
    r'^\d+\.\s*\n\d+\.\s*\n',           # "1.\n2.\n3." → table des matières
    r'^(Motivation|Success Stories|Outcomes|Collaboration)',
    r'^(Table of Contents|Contents|Index)',
    r'^(Phase \d|Step \d|Section \d)',
    r'^Q\d+ - ',                          # Questions de framework
    r'^\s*•\s*\n\s*•\s*\n',             # Listes à puces vides
]

# Sources légitimes qui ne contiennent PAS de malware réel
LEGITIMATE_SOURCES = {
    "practical_malware_analysis.pdf",
    "MASIG-MalwareAnalysisFramework.pdf",
    "Malware Analysis.pdf",
    "Malware Analysis Management.pdf",
}

# Patterns de description polluée pour les livres d'exercice
BOOK_DESCRIPTION_NOISE = [
    "PE header", "static analysis", "Table 1-", "Chapter ",
    "Test Objective", "Test Scope", "Testing Methodology",
    "Result Summary", "Conclusion", "Recommendations",
]


# ─────────────────────────────────────────────────────────────
# CLASSE PRINCIPALE
# ─────────────────────────────────────────────────────────────

class DataQualityFilter:
    """
    Filtre et corrige automatiquement les records du knowledge_base.json.
    
    Étapes :
    1. Valider et nettoyer les IOCs
    2. Corriger les fausses familles malware
    3. Corriger les descriptions inutilisables
    4. Re-générer les embedding_text corrects
    5. Re-calculer la confiance
    6. Classifier les records : high / medium / low / rejected
    7. Exporter les datasets stratifiés
    """

    def __init__(self):
        self.stats = {
            "total_input": 0,
            "total_output": 0,
            "rejected": 0,
            "iocs_cleaned": 0,
            "families_corrected": 0,
            "descriptions_fixed": 0,
            "embeddings_regenerated": 0,
            "confidence_changed": 0,
        }

    # ─────────────────────────────────────────────────────────
    # PIPELINE PRINCIPAL
    # ─────────────────────────────────────────────────────────

    def process(self, records: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Traite tous les records et retourne un dict stratifié :
        {
            'high':     [...],   # records prêts pour la production
            'medium':   [...],   # records utilisables avec précaution
            'low':      [...],   # records à vérifier manuellement
            'rejected': [...],   # records écartés (trop bruités)
        }
        """
        self.stats["total_input"] = len(records)
        
        processed = []
        rejected  = []

        for record in records:
            result = self._process_record(record)
            if result is None:
                rejected.append(record)
                self.stats["rejected"] += 1
            else:
                processed.append(result)

        # Stratifier par confiance finale
        stratified = {
            "high":     [r for r in processed if r["confidence"] == "high"],
            "medium":   [r for r in processed if r["confidence"] == "medium"],
            "low":      [r for r in processed if r["confidence"] == "low"],
            "rejected": rejected,
        }

        self.stats["total_output"] = len(processed)
        return stratified

    def _process_record(self, record: Dict) -> Optional[Dict]:
        """Traite un seul record. Retourne None si le record doit être rejeté."""
        r = dict(record)  # copie pour ne pas modifier l'original

        # Étape 1 : Nettoyer les IOCs
        r = self._clean_iocs(r)

        # Étape 2 : Corriger la famille malware
        r = self._fix_malware_family(r)

        # Étape 3 : Corriger la description
        r = self._fix_description(r)

        # Étape 4 : Re-générer l'embedding_text
        r = self._regenerate_embedding(r)

        # Étape 5 : Re-calculer la confiance
        r = self._recompute_confidence(r)

        # Étape 6 : Décider si on rejette
        if self._should_reject(r):
            return None

        return r

    # ─────────────────────────────────────────────────────────
    # ÉTAPE 1 : NETTOYAGE IOCs
    # ─────────────────────────────────────────────────────────

    def _clean_iocs(self, record: Dict) -> Dict:
        """Filtre les IOCs légitimes / bruit des records."""
        iocs = record.get("ioc", [])
        if not iocs:
            return record

        original_count = len(iocs)
        cleaned = []

        for ioc in iocs:
            ioc_str = str(ioc).strip()
            if self._is_real_ioc(ioc_str, record):
                cleaned.append(ioc_str)

        # Cap à MAX_IOC_COUNT pour éviter les records-livres avec 264 IOCs
        if len(cleaned) > MAX_IOC_COUNT:
            # Prioriser : IPs > hashes > domaines suspects > chemins malveillants
            cleaned = self._prioritize_iocs(cleaned, MAX_IOC_COUNT)

        if len(cleaned) != original_count:
            self.stats["iocs_cleaned"] += 1

        record["ioc"] = cleaned
        return record

    def _is_real_ioc(self, ioc: str, record: Dict) -> bool:
        """Détermine si un IOC est réel (malveillant) ou un artefact."""
        
        # 1. Domaines d'outils légitimes
        ioc_lower = ioc.lower()
        for legit in LEGITIMATE_TOOL_DOMAINS:
            if legit in ioc_lower:
                return False

        # 2. Chemins Windows système standard (sans composant malveillant)
        if re.match(r'[Cc]:\\[Ww]indows\\[Ss]ystem32\\', ioc):
            dll_name = ioc.split('\\')[-1].lower()
            legit_system_files = {
                "kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll",
                "gdi32.dll", "ws2_32.dll", "shell32.dll", "msvcrt.dll",
                "wininet.dll", "ntoskrnl.exe", "winlogon.exe", "services.exe",
                "svchost.exe", "lsass.exe", "explorer.exe", "cmd.exe",
                "powershell.exe", "wscript.exe", "mshta.exe",
            }
            if dll_name in legit_system_files:
                return False

        # 3. Chemins d'exercices livres
        exercise_paths = [
            r'c:\\temp\\cc\.exe', r'c:\\windows\\evil\.exe',
            r'z:\\malware', r'c:\\websymbols', r'c:\\docs\b',
            r'c:\\secretfile\.txt', r'c:\\encrypted_file\b',
            r'c:\\documents and settings\\user\\desktop',
            r'c:\\users\\user1',
        ]
        for ep in exercise_paths:
            if re.search(ep, ioc_lower):
                return False

        # 4. Emails de contact institutionnel (pas des IOCs)
        if re.match(r'[a-z]+@[a-z]+\.(gov|edu|org)\.[a-z]{2}$', ioc_lower):
            return False

        # 5. IPs privées/locales
        private_patterns = [
            r'^127\.', r'^10\.', r'^192\.168\.', r'^172\.(1[6-9]|2\d|3[01])\.',
            r'^0\.0\.0\.', r'^255\.255\.255\.', r'^169\.254\.',
        ]
        for pp in private_patterns:
            if re.match(pp, ioc):
                return False

        # 6. Hashes de test (all-zeros, séquences répétées)
        if re.match(r'^[a-fA-F0-9]{32,64}$', ioc):
            if len(set(ioc.lower())) <= 3:  # ex: "12999999999..." 
                return False
            # Vérifier si c'est un vrai hash (entropie suffisante)
            unique_chars = len(set(ioc.lower()))
            if unique_chars < 8:
                return False

        return True

    def _prioritize_iocs(self, iocs: List[str], limit: int) -> List[str]:
        """Priorise les IOCs par pertinence quand il y en a trop."""
        def score(ioc: str) -> int:
            # IPs publiques → score 4
            if re.match(r'(?:\d{1,3}\.){3}\d{1,3}$', ioc):
                return 4
            # Hashes → score 3
            if re.match(r'[a-fA-F0-9]{32,64}$', ioc):
                return 3
            # Domaines suspects (pas dans la whitelist) → score 2
            if re.search(r'\.(onion|ru|cn|xyz|top)\b', ioc.lower()):
                return 2
            # Chemins avec noms suspects → score 2
            if re.search(r'(mal|evil|hack|crack|payload|c2|ransom)', ioc.lower()):
                return 2
            # Clés de registre → score 1
            if ioc.startswith('HKEY_'):
                return 1
            return 0

        scored = sorted(iocs, key=score, reverse=True)
        return scored[:limit]

    # ─────────────────────────────────────────────────────────
    # ÉTAPE 2 : CORRECTION FAMILLE MALWARE
    # ─────────────────────────────────────────────────────────

    def _fix_malware_family(self, record: Dict) -> Dict:
        """Corrige les fausses familles détectées par erreur."""
        family = record.get("malware_family", "unknown")
        source = record.get("source_document", "")
        
        # Cas 1 : la source est un livre/doc pédagogique
        # Les familles extraites sont probablement des mentions, pas des sujets
        if source in LEGITIMATE_SOURCES:
            # Vérifier que la famille est vraiment le sujet du document
            yara_rule = record.get("yara_rule", "")
            desc = record.get("description", "")
            
            if family != "unknown" and family in KNOWN_MALWARE_FAMILIES:
                # Compter les occurrences dans description + YARA
                family_occurrences = desc.lower().count(family.lower()) + \
                                    yara_rule.lower().count(family.lower())
                
                if family_occurrences < 2:
                    # Une seule mention = probablement une référence, pas le sujet
                    old_family = family
                    record["malware_family"] = "unknown"
                    record.setdefault("_corrections", []).append(
                        f"family '{old_family}' changed to 'unknown' "
                        f"(pedagogical source, only {family_occurrences} occurrence(s))"
                    )
                    self.stats["families_corrected"] += 1

        # Cas 2 : famille "Backdoor" trop générique (c'est un type, pas une famille)
        if family == "Backdoor":
            # "Backdoor" dans les YARA = type, pas famille
            # Essayer d'extraire une vraie famille du nom de règle YARA
            better_family = self._extract_family_from_yara_name(record)
            if better_family and better_family != "Backdoor":
                record["malware_family"] = better_family
                self.stats["families_corrected"] += 1
            # else: laisser "Backdoor" (c'est mieux que "unknown")

        return record

    def _extract_family_from_yara_name(self, record: Dict) -> Optional[str]:
        """Essaie d'extraire la famille depuis le nom de la règle YARA ou le filename."""
        yara_rule = record.get("yara_rule", "")
        source_doc = record.get("source_document", "")
        
        # Chercher dans le nom de la règle
        rule_names = re.findall(r'rule\s+(\w+)', yara_rule)
        candidates = rule_names + [source_doc.replace('.yar', '').replace('.yara', '')]
        
        for candidate in candidates:
            # Vérifier si un nom de famille connu est dans le nom de règle
            for known in KNOWN_MALWARE_FAMILIES:
                if known.lower() in candidate.lower() and known not in {"Backdoor", "Trojan"}:
                    return known
        
        return None

    # ─────────────────────────────────────────────────────────
    # ÉTAPE 3 : CORRECTION DESCRIPTION
    # ─────────────────────────────────────────────────────────

    def _fix_description(self, record: Dict) -> Dict:
        """Remplace les descriptions inutiles par une description générée."""
        desc = record.get("description", "")
        
        # Vérifier si la description est du bruit
        if self._is_useless_description(desc):
            new_desc = self._generate_fallback_description(record)
            if new_desc and len(new_desc) > MIN_DESCRIPTION_LENGTH:
                record["description"] = new_desc
                self.stats["descriptions_fixed"] += 1
        
        return record

    def _is_useless_description(self, desc: str) -> bool:
        """Détecte si une description est inutilisable."""
        if not desc or len(desc) < MIN_DESCRIPTION_LENGTH:
            return True
        
        if desc in ("No description available", ""):
            return True
        
        # Patterns de bruit
        for pattern in USELESS_DESCRIPTION_PATTERNS:
            if re.match(pattern, desc, re.IGNORECASE | re.MULTILINE):
                return True
        
        # Bruit des livres d'exercices
        for noise in BOOK_DESCRIPTION_NOISE:
            if desc.startswith(noise):
                return True
        
        # Table des matières : beaucoup de "\n\d+\."
        toc_lines = re.findall(r'\n\d+[\.\)]\s', desc)
        if len(toc_lines) >= 3:
            return True
        
        # Vérifier densité de mots cybersécurité
        cyber_words = {
            'malware', 'ransomware', 'trojan', 'backdoor', 'exploit',
            'vulnerability', 'attack', 'threat', 'infection', 'payload',
            'encrypt', 'c2', 'command', 'shellcode', 'yara', 'ioc',
            'apt', 'rule', 'detection', 'signature',
        }
        desc_lower = desc.lower()
        cyber_density = sum(1 for w in cyber_words if w in desc_lower)
        
        if cyber_density == 0 and len(desc) < 200:
            return True
        
        return False

    def _generate_fallback_description(self, record: Dict) -> str:
        """Génère une description de fallback depuis les autres champs."""
        parts = []
        
        # 1. Depuis le meta: YARA
        yara_rule = record.get("yara_rule", "")
        if yara_rule:
            meta_desc = self._extract_yara_meta_description(yara_rule)
            if meta_desc:
                return meta_desc
        
        # 2. Construire depuis les champs structurés
        family = record.get("malware_family", "unknown")
        mtype  = record.get("malware_type", "unknown")
        stage  = record.get("attack_stage", "unknown")
        behaviors = record.get("behavior_summary", [])
        
        if family != "unknown" and mtype != "unknown":
            parts.append(f"{family} {mtype}")
        elif mtype != "unknown":
            parts.append(f"{mtype.capitalize()} malware")
        elif family != "unknown":
            parts.append(f"{family} malware")
        
        if behaviors:
            top_behaviors = behaviors[:3]
            parts.append(f"performing {', '.join(top_behaviors)}")
        
        if stage != "unknown":
            parts.append(f"at {stage} stage")
        
        # 3. Depuis le nom du fichier source YARA
        if not parts:
            source = record.get("source_document", "")
            if source.endswith(('.yar', '.yara')):
                name = source.replace('.yar', '').replace('.yara', '')
                # Convertir snake_case en phrase
                readable = re.sub(r'[_\-]+', ' ', name)
                readable = re.sub(r'\b(rule|detect|yara|mal)\b', '', readable, flags=re.I)
                readable = readable.strip()
                if len(readable) > 10:
                    parts.append(f"YARA rule for detecting {readable}")
        
        return ". ".join(parts).capitalize() if parts else ""

    def _extract_yara_meta_description(self, yara_text: str) -> str:
        """Extrait le champ description du bloc meta: YARA."""
        meta_match = re.search(
            r'meta\s*:(.*?)(?:strings\s*:|condition\s*:)',
            yara_text, re.DOTALL
        )
        if not meta_match:
            return ""
        
        meta_block = meta_match.group(1)
        match = re.search(r'description\s*=\s*"([^"]{15,})"', meta_block, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        
        return ""

    # ─────────────────────────────────────────────────────────
    # ÉTAPE 4 : RE-GÉNÉRATION EMBEDDING_TEXT
    # ─────────────────────────────────────────────────────────

    def _regenerate_embedding(self, record: Dict) -> Dict:
        """Re-génère un embedding_text propre depuis les champs corrigés."""
        original = record.get("embedding_text", "")
        
        parts = []
        
        # Description nettoyée (max 250 chars)
        desc = record.get("description", "")
        if desc and not self._is_useless_description(desc):
            clean_desc = desc[:250].strip()
            parts.append(clean_desc)
        
        # Famille ×2 (ancre principale pour retrieval)
        family = record.get("malware_family", "unknown")
        if family not in ("unknown", ""):
            parts.extend([family, family])
        
        # Type ×1
        mtype = record.get("malware_type", "unknown")
        if mtype not in ("unknown", "", "generic", "documentation"):
            parts.append(mtype)
        
        # Noms des règles YARA (ancres sémantiques)
        yara_names = self._extract_yara_rule_names(record.get("yara_rule", ""))
        parts.extend(yara_names[:3])
        
        # Comportements (max 5)
        behaviors = record.get("behavior_summary", [])
        parts.extend(str(b) for b in behaviors[:5])
        
        # Attack stage
        stage = record.get("attack_stage", "unknown")
        if stage not in ("unknown", ""):
            parts.append(stage)
        
        # IOCs filtrés (max 6 — on prend les plus pertinents)
        iocs = record.get("ioc", [])
        relevant_iocs = self._select_relevant_iocs_for_embedding(iocs, 6)
        parts.extend(relevant_iocs)
        
        # Strings/patterns significatifs (max 5)
        patterns = record.get("strings_or_patterns", [])
        clean_patterns = [
            p for p in patterns
            if isinstance(p, str)
            and len(p) > 4
            and not p.startswith("hex:")
            and len(re.findall(r'[A-Za-z]', p)) >= 3
        ]
        parts.extend(clean_patterns[:5])
        
        # Déduplication ordonnée
        seen = set()
        unique = []
        for p in parts:
            p_norm = str(p).lower().strip()
            if p_norm and p_norm not in seen:
                seen.add(p_norm)
                unique.append(str(p))
        
        new_embedding = re.sub(r'\s+', ' ', " ".join(unique)).lower().strip()
        
        if new_embedding != original.lower().strip():
            self.stats["embeddings_regenerated"] += 1
        
        record["embedding_text"] = new_embedding
        return record

    def _extract_yara_rule_names(self, yara_text: str) -> List[str]:
        """Extrait les noms lisibles des règles YARA."""
        if not yara_text:
            return []
        
        names = re.findall(r'rule\s+(\w+)', yara_text)
        readable = []
        
        for name in names[:3]:
            tokens = re.split(r'[_\-]+', name)
            # Filtrer les mots génériques
            filtered = [
                t for t in tokens
                if len(t) > 2
                and t.lower() not in {
                    'apt', 'mal', 'gen', 'susp', 'expl', 'crime', 'win', 'linux',
                    'elf', 'doc', 'pdb', 'the', 'and', 'for', 'yar', 'rule',
                    'detection', 'detect', 'detects', 'unknown', 'generic',
                }
            ]
            if filtered:
                readable.append(' '.join(filtered))
        
        return readable

    def _select_relevant_iocs_for_embedding(self, iocs: List[str], limit: int) -> List[str]:
        """Sélectionne les IOCs les plus informatifs pour l'embedding."""
        if not iocs:
            return []
        
        def relevance(ioc: str) -> int:
            # Domaines malveillants (onion, .ru, noms suspects)
            if re.search(r'\.(onion|ru|cn|xyz|top|pw|biz)\b', ioc.lower()):
                return 5
            # Hashes MD5/SHA256
            if re.match(r'[a-fA-F0-9]{32,64}$', ioc):
                return 4
            # IPs publiques
            if re.match(r'(?:\d{1,3}\.){3}\d{1,3}$', ioc):
                return 3
            # Noms de fichiers malveillants
            if re.search(r'(evil|mal|hack|ransom|payload|c2|locker)', ioc.lower()):
                return 3
            # Clés de registre
            if ioc.startswith("HKEY_"):
                return 2
            # Chemins Windows non-système
            if re.match(r'[A-Za-z]:\\', ioc) and len(ioc) > 20:
                return 1
            return 0
        
        scored = sorted(iocs, key=relevance, reverse=True)
        return [ioc for ioc in scored[:limit] if relevance(ioc) > 0]

    # ─────────────────────────────────────────────────────────
    # ÉTAPE 5 : RE-CALCUL CONFIANCE
    # ─────────────────────────────────────────────────────────

    def _recompute_confidence(self, record: Dict) -> Dict:
        """Re-calcule le score de confiance après corrections."""
        old_conf = record.get("confidence", "low")
        score = 0
        
        family = record.get("malware_family", "unknown")
        mtype  = record.get("malware_type", "unknown")
        iocs   = record.get("ioc", [])
        behaviors = record.get("behavior_summary", [])
        yara_rule = record.get("yara_rule", "")
        stage  = record.get("attack_stage", "unknown")
        patterns  = record.get("strings_or_patterns", [])
        desc   = record.get("description", "")
        
        # Critères pondérés
        if family not in ("unknown", "") and family in KNOWN_MALWARE_FAMILIES:
            score += 2  # famille reconnue = +2 (très important)
        elif family not in ("unknown", ""):
            score += 1  # famille non-reconnue mais présente = +1
        
        if mtype not in ("unknown", "", "generic", "suspicious", "documentation"):
            score += 1
        
        if len(iocs) >= 1:
            score += 1
        if len(iocs) >= 3:
            score += 1  # bonus IOCs multiples
        
        if len(behaviors) >= 2:
            score += 1
        
        if yara_rule and len(yara_rule) > 80:
            score += 2  # règle YARA complète = très bon signal
        
        if stage not in ("unknown", ""):
            score += 1
        
        if len(patterns) >= 2:
            score += 1
        
        if len(desc) > 100 and not self._is_useless_description(desc):
            score += 1
        
        # Mapping score → confiance
        if score >= 6:
            new_conf = "high"
        elif score >= 3:
            new_conf = "medium"
        else:
            new_conf = "low"
        
        if new_conf != old_conf:
            self.stats["confidence_changed"] += 1
        
        record["confidence"] = new_conf
        return record

    # ─────────────────────────────────────────────────────────
    # ÉTAPE 6 : DÉCISION DE REJET
    # ─────────────────────────────────────────────────────────

    def _should_reject(self, record: Dict) -> bool:
        """Détermine si un record doit être entièrement rejeté."""
        
        # Règle 1 : embedding_text trop court
        embedding = record.get("embedding_text", "")
        if len(embedding) < MIN_EMBEDDING_LENGTH:
            return True
        
        # Règle 2 : Pas de YARA ET pas d'IOC ET pas de famille
        has_yara = bool(record.get("yara_rule", ""))
        has_ioc  = bool(record.get("ioc", []))
        has_family = record.get("malware_family", "unknown") != "unknown"
        
        if not has_yara and not has_ioc and not has_family:
            return True
        
        # Règle 3 : Record de documentation pure (pas de contenu cybersécurité)
        mtype = record.get("malware_type", "unknown")
        if mtype == "documentation" and not has_yara:
            return True
        
        # Règle 4 : Description + embedding complètement vides
        desc = record.get("description", "")
        if not desc and not embedding:
            return True
        
        # Rejeter la documentation YARA pure
        if record.get('source_type') == 'yara_documentation':
            return True
        
        return False

    # ─────────────────────────────────────────────────────────
    # RAPPORT
    # ─────────────────────────────────────────────────────────

    def print_report(self, stratified: Dict[str, List[Dict]]):
        """Affiche le rapport qualité du filtrage."""
        total_in  = self.stats["total_input"]
        total_out = self.stats["total_output"]
        
        print("\n" + "=" * 65)
        print("📊 RAPPORT DE FILTRAGE QUALITÉ")
        print("=" * 65)
        print(f"\n  Records en entrée     : {total_in}")
        print(f"  Records conservés     : {total_out} ({total_out/total_in*100:.1f}%)")
        print(f"  Records rejetés       : {self.stats['rejected']} ({self.stats['rejected']/total_in*100:.1f}%)")
        
        print(f"\n  Corrections appliquées :")
        print(f"    IOCs nettoyés         : {self.stats['iocs_cleaned']}")
        print(f"    Familles corrigées    : {self.stats['families_corrected']}")
        print(f"    Descriptions fixées  : {self.stats['descriptions_fixed']}")
        print(f"    Embeddings régénérés : {self.stats['embeddings_regenerated']}")
        print(f"    Confiances modifiées : {self.stats['confidence_changed']}")
        
        print(f"\n  Distribution par confiance :")
        for tier, records in stratified.items():
            count = len(records)
            pct   = count / total_in * 100 if total_in > 0 else 0
            bar   = "█" * int(pct / 2)
            print(f"    {tier:10} : {count:4d} ({pct:5.1f}%) {bar}")
        
        # Statistiques post-filtrage
        all_records = stratified["high"] + stratified["medium"] + stratified["low"]
        if all_records:
            with_family  = sum(1 for r in all_records if r.get("malware_family", "unknown") != "unknown")
            with_yara    = sum(1 for r in all_records if r.get("yara_rule", ""))
            with_ioc     = sum(1 for r in all_records if r.get("ioc", []))
            avg_emb      = sum(len(r.get("embedding_text", "")) for r in all_records) / len(all_records)
            
            print(f"\n  Statistiques post-filtrage :")
            print(f"    Avec famille      : {with_family} ({with_family/len(all_records)*100:.1f}%)")
            print(f"    Avec règle YARA   : {with_yara} ({with_yara/len(all_records)*100:.1f}%)")
            print(f"    Avec IOC(s)       : {with_ioc} ({with_ioc/len(all_records)*100:.1f}%)")
            print(f"    Embedding moyen   : {avg_emb:.0f} chars")
        
        print("\n" + "=" * 65)


# ─────────────────────────────────────────────────────────────
# EXPORTS
# ─────────────────────────────────────────────────────────────

def export_datasets(stratified: Dict[str, List[Dict]], output_dir: Path):
    """
    Exporte 3 fichiers :
    - dataset_production.json     → high + medium (prêt RAG)
    - dataset_high_quality.json   → high uniquement (gold standard)
    - dataset_rejected.json       → records rejetés (pour audit)
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Dataset production (high + medium)
    production = stratified["high"] + stratified["medium"]
    _save_json(production, output_dir / "dataset_production.json")
    
    # Dataset gold standard (high uniquement)
    _save_json(stratified["high"], output_dir / "dataset_high_quality.json")
    
    # Dataset rejeté (pour audit manuel)
    _save_json(stratified["rejected"], output_dir / "dataset_rejected.json")
    
    # Dataset complet filtré (high + medium + low)
    all_valid = production + stratified["low"]
    _save_json(all_valid, output_dir / "dataset_all_filtered.json")
    
    print(f"\n💾 Exports :")
    print(f"   dataset_production.json   → {len(production)} records (high + medium)")
    print(f"   dataset_high_quality.json → {len(stratified['high'])} records (gold)")
    print(f"   dataset_all_filtered.json → {len(all_valid)} records")
    print(f"   dataset_rejected.json     → {len(stratified['rejected'])} records (audit)")


def _save_json(records: List[Dict], path: Path):
    """Sauvegarde un fichier JSON proprement."""
    # Nettoyer les champs internes avant export
    clean_records = []
    for r in records:
        clean_r = {k: v for k, v in r.items() if not k.startswith("_")}
        clean_records.append(clean_r)
    
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(clean_records, f, indent=2, ensure_ascii=False)
    
    size_kb = path.stat().st_size / 1024
    print(f"   ✓ {path.name:45} {len(clean_records):4d} records | {size_kb:.0f} Ko")


# ─────────────────────────────────────────────────────────────
# POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────

def main():
    # Chemins
    input_path  = Path("data/processed/knowledge_base.json")
    output_dir  = Path("data/processed/filtered")
    
    if not input_path.exists():
        print(f"❌ Fichier introuvable : {input_path}")
        print("   Exécutez d'abord : python run_preprocessing.py")
        sys.exit(1)
    
    print("=" * 65)
    print("🔍 DATA QUALITY FILTER — NLP Pipeline")
    print("=" * 65)
    print(f"   Entrée : {input_path}")
    print(f"   Sortie : {output_dir}/")
    
    # Charger le JSON
    with open(input_path, 'r', encoding='utf-8') as f:
        records = json.load(f)
    
    print(f"\n   {len(records)} records chargés...")
    
    # Filtrer
    filter_engine = DataQualityFilter()
    stratified = filter_engine.process(records)
    
    # Rapport
    filter_engine.print_report(stratified)
    
    # Exporter
    export_datasets(stratified, output_dir)
    
    # Message final
    production_count = len(stratified["high"]) + len(stratified["medium"])
    print(f"\n✅ Filtrage terminé.")
    print(f"   → Livrez dataset_production.json ({production_count} records) à l'équipe RAG")
    print(f"   → Auditez dataset_rejected.json manuellement si besoin")


if __name__ == "__main__":
    main()