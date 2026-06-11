# src/preprocessing/embedding_text_gen.py
# v4 — corrections :
#   1. Déduplication des parties (évite la répétition excessive)
#   2. Pondération par source_type (YARA vs rapport)
#   3. Inclusion systématique du nom de règle YARA
#   4. Filtrage amélioré des strings hex

import re
from typing import Dict, List


def _is_embedding_worthy_ioc(ioc: str) -> bool:
    """Filtre les IOCs avant injection dans l'embedding_text."""
    if not ioc or len(ioc) < 4:
        return False
    if ioc.startswith('/'):
        return False
    if re.match(r'^[\s/\.\-_]+$', ioc):
        return False
    if any(kw in ioc for kw in ['struct.', 'sys.argv', 'gzip.open', 'import ', 'print(']):
        return False

    ip_pattern = re.match(r'(?:\d{1,3}\.){3}\d{1,3}', ioc)
    domain_pattern = re.search(
        r'(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|gov|edu|io|uk|onion)\b', ioc
    )
    hash_pattern = re.match(r'[a-fA-F0-9]{32,64}$', ioc)
    win_path = re.match(r'[A-Za-z]:\\', ioc)
    registry = re.match(r'HKEY_', ioc)
    suspicious_file = re.match(r'\w+\.(?:exe|dll|bat|ps1|vbs|scr)', ioc, re.IGNORECASE)
    command = 'vssadmin' in ioc.lower() or 'schtasks' in ioc.lower()

    return bool(ip_pattern or domain_pattern or hash_pattern or win_path
                or registry or suspicious_file or command or len(ioc) > 20)


def _extract_yara_rule_names(yara_text: str) -> List[str]:
    """Extrait les noms des règles YARA pour les inclure comme ancres."""
    if not yara_text:
        return []
    names = re.findall(r'rule\s+(\w+)', yara_text)
    readable = []
    for name in names[:3]:  # max 3 noms (réduit pour éviter le bruit)
        tokens = re.split(r'[_\-]+', name)
        tokens = [t for t in tokens if len(t) > 2 and t.lower() not in {
            'apt', 'mal', 'gen', 'susp', 'expl', 'crime', 'win', 'linux',
            'elf', 'doc', 'pdb', 'the', 'and', 'for', 'yar', 'rule',
            'detection', 'detect', 'detects', 'unknown',
        }]
        if tokens:
            readable.append(' '.join(tokens))
    return readable


def _extract_yara_meta_keywords(yara_text: str) -> List[str]:
    """Extrait les mots-clés pertinents depuis le bloc meta: YARA."""
    if not yara_text:
        return []
    
    meta_match = re.search(r'meta\s*:(.*?)(?:strings\s*:|condition\s*:)', yara_text, re.DOTALL)
    if not meta_match:
        return []
    
    meta_block = meta_match.group(1)
    keywords = []
    
    # Extraire description, author, reference comme contexte
    for field in ['description', 'author', 'reference', 'source']:
        pattern = rf'{field}\s*=\s*"([^"]{{10,200}})"'
        match = re.search(pattern, meta_block, re.IGNORECASE)
        if match:
            value = match.group(1)
            # Extraire les mots significatifs
            words = re.findall(r'\b[A-Za-z]{3,}\b', value)
            keywords.extend([w.lower() for w in words if w.lower() not in {
                'the', 'and', 'for', 'with', 'this', 'that', 'from', 'http',
                'https', 'com', 'org', 'net', 'www', 'github', 'blog',
            }])
    
    return list(dict.fromkeys(keywords))[:10]


def generate_embedding_text(record: Dict) -> str:
    """
    Génère le champ embedding_text — v4 optimisé.
    """
    parts: List[str] = []
    source_type = record.get('source_type', '')
    is_yara = source_type in ('yara_cybersecurity_rule', 'yara_rule', 'yara_misc')
    
    # 1. Description — poids ×1 (pas ×2 pour éviter la redondance)
    desc = record.get('description', '').strip()
    if desc and desc not in ('No description available', ''):
        # Tronquer les descriptions trop longues
        if len(desc) > 300:
            desc = desc[:300]
        parts.append(desc)
    
    # 2. Famille malware — poids ×2 (important pour le retrieval)
    family = record.get('malware_family', '')
    if family and family not in ('unknown', 'yara_documentation'):
        parts.append(family)
        parts.append(family)
    
    # 3. Type malware — poids ×1
    mtype = record.get('malware_type', '')
    if mtype and mtype not in ('unknown', 'documentation'):
        parts.append(mtype)
    
    # 4. Noms des règles YARA — ancres sémantiques
    yara_names = _extract_yara_rule_names(record.get('yara_rule', ''))
    parts.extend(yara_names)
    
    # 5. Mots-clés du meta: YARA
    if is_yara:
        meta_keywords = _extract_yara_meta_keywords(record.get('yara_rule', ''))
        parts.extend(meta_keywords)
    
    # 6. Comportements — cap à 5
    behaviors = record.get('behavior_summary', [])
    if behaviors:
        parts.extend(str(b) for b in behaviors[:5])
    
    # 7. Stage d'attaque
    stage = record.get('attack_stage', '')
    if stage and stage != 'unknown':
        parts.append(stage)
    
    # 8. IOCs filtrés — cap à 8 (réduit)
    iocs = record.get('ioc', [])
    clean_iocs = [ioc for ioc in iocs if _is_embedding_worthy_ioc(str(ioc))]
    parts.extend(clean_iocs[:8])
    
    # 9. Strings/patterns — filtrage strict
    patterns = record.get('strings_or_patterns', [])
    meaningful_patterns = []
    for p in patterns:
        if not isinstance(p, str) or len(p) <= 3:
            continue
        if p.startswith('hex:'):
            continue  # Les hex ne sont pas sémantiquement utiles
        if p.startswith('regex:'):
            # Garder les regex mais nettoyer
            clean_p = p[6:].replace('\\', ' ').replace('.', ' ')
            if len(clean_p) > 5:
                meaningful_patterns.append(clean_p)
            continue
        # Filtrer les strings trop techniques/binaires
        if re.match(r'^[\x00-\x1f\x7f]+$', p):
            continue
        if len(re.findall(r'[A-Za-z]', p)) < 3:  # Au moins 3 lettres
            continue
        meaningful_patterns.append(p)
    
    parts.extend(meaningful_patterns[:6])
    
    # Déduplication tout en préservant l'ordre
    seen = set()
    unique_parts = []
    for p in parts:
        p_lower = str(p).lower().strip()
        if p_lower and p_lower not in seen:
            seen.add(p_lower)
            unique_parts.append(str(p))
    
    embedding_text = " ".join(unique_parts)
    embedding_text = re.sub(r'\s+', ' ', embedding_text)
    embedding_text = embedding_text.lower().strip()
    
    return embedding_text


def validate_embedding_text(text: str,
                              min_length: int = 40,
                              source_type: str = '') -> bool:
    """
    v4 : seuil adaptatif avec vérification de diversité.
    """
    is_yara = source_type in ('yara_cybersecurity_rule', 'yara_rule', 'yara_misc')
    threshold = min_length if is_yara else 80

    if len(text) < threshold:
        return False

    words = text.split()
    real_words = [w for w in words if re.match(r'[a-zA-Z]{2,}', w)]
    
    # Vérifier la diversité (pas juste la répétition)
    unique_real_words = set(real_words)
    if len(unique_real_words) < 3:
        return False
    
    return len(real_words) >= 3


def get_embedding_stats(record: Dict) -> Dict:
    text = record.get('embedding_text', '')
    words = text.split()
    unique_words = set(words)
    
    # Calculer le taux de répétition
    repetition_rate = 1 - (len(unique_words) / len(words)) if words else 0
    
    return {
        'total_chars': len(text),
        'total_words': len(words),
        'unique_words': len(unique_words),
        'repetition_rate': round(repetition_rate, 2),
        'has_family': record.get('malware_family', 'unknown') != 'unknown',
        'has_type': record.get('malware_type', 'unknown') != 'unknown',
        'ioc_count_filtered': len([
            ioc for ioc in record.get('ioc', [])
            if _is_embedding_worthy_ioc(str(ioc))
        ]),
        'valid': validate_embedding_text(text, source_type=record.get('source_type', '')),
    }