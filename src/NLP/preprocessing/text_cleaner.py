# src/preprocessing/text_cleaner.py


import re


class TextCleaner:
    def __init__(self):
        # Patterns bruit pur (sans valeur cybersécurité)
        self.noise_patterns = [
            r'Page\s+\d+\s+of\s+\d+',             # Numéros de page PDF
            r'©\s*.{0,50}(?:All\s+rights?\s+reserved|reserved)\.?',  # Copyright
            r'CONFIDENTIAL\s*[-–]\s*TLP\s*:\s*\w+',  # Marqueurs TLP
            r'\bDRAFT\b',                          # Marqueur brouillon
            r'^\s*\d+\s*$',                        # Lignes contenant uniquement un numéro
        ]

        # Artefacts de rendu PDF courants
        self.pdf_artifacts = [
            r'\(cid:\d+\)',                        # Caractères non rendus
            r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', # Caractères de contrôle (sauf \t, \n, \r)
            r'f\s+f\s+f\b',                        # Ligature ff mal rendue
            r'fi\b(?=\w)',                         # Ligature fi mal rendue (partiel)
        ]

    def clean(self, text: str) -> str:
        """
        Pipeline de nettoyage.
        IMPORTANT : ne pas supprimer les URLs (IOCs potentiels).
        Ne pas supprimer les dates (contexte temporel).
        """
        if not text:
            return ""

        # 1. Supprimer les artefacts PDF
        for pattern in self.pdf_artifacts:
            text = re.sub(pattern, ' ', text)

        # 2. Normaliser les sauts de ligne multiples (max 2)
        text = re.sub(r'\n{3,}', '\n\n', text)

        # 3. Supprimer le bruit pur
        for pattern in self.noise_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE | re.MULTILINE)

        # 4. Normaliser les espaces horizontaux (pas les sauts de ligne)
        text = re.sub(r'[ \t]+', ' ', text)

        # 5. Normaliser la ponctuation (espace après virgule/point si absent)
        text = re.sub(r'([,;:])(?=[^\s])', r'\1 ', text)

        # 6. Supprimer les lignes vides résiduelle en début/fin
        text = '\n'.join(line.rstrip() for line in text.split('\n'))
        text = re.sub(r'\n{3,}', '\n\n', text)

        return text.strip()

    def clean_for_extraction(self, text: str) -> str:
        """
        Version plus agressive pour améliorer l'extraction NLP.
        - Supprime les blocs de code binaire/hex (pour ne pas polluer les extractions)
        - Garde les IOCs et patterns YARA
        """
        cleaned = self.clean(text)

        # Supprimer les gros blocs hex (> 30 octets consécutifs sans saut de ligne)
        # qui polluent l'extraction de phrases
        cleaned = re.sub(
            r'(?:[0-9A-Fa-f]{2}\s+){10,}[0-9A-Fa-f]{2}',
            '[HEX_BLOCK]',
            cleaned
        )

        # Supprimer les traces de stack/code Python brut
        cleaned = re.sub(
            r'(?:struct\.(?:pack|unpack)\([^\)]+\)\s*)+',
            ' ',
            cleaned
        )

        return cleaned.strip()

    def clean_yara_rule(self, rule_text: str) -> str:
        """Nettoie une règle YARA en préservant sa syntaxe."""
        # Supprimer les commentaires inline
        rule_text = re.sub(r'//[^\n]*', '', rule_text, flags=re.MULTILINE)
        # Supprimer les commentaires multi-lignes
        rule_text = re.sub(r'/\*.*?\*/', '', rule_text, flags=re.DOTALL)
        # Normaliser les espaces internes
        rule_text = re.sub(r'[ \t]+', ' ', rule_text)
        rule_text = re.sub(r'\n{3,}', '\n\n', rule_text)
        return rule_text.strip()

    def extract_text_sentences_only(self, text: str) -> str:
        """
        Retourne uniquement les phrases en langue naturelle,
        en supprimant les blocs de code et les règles YARA.
        Utile pour la détection de langue et les descriptions.
        """
        # Supprimer les règles YARA
        text = re.sub(r'rule\s+\w+\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\}', '', text, flags=re.DOTALL)
        # Supprimer les blocs hex
        text = re.sub(r'\{[0-9A-Fa-f\s]{10,}\}', '', text)
        # Supprimer les lignes de code Python
        text = re.sub(r'(?:import\s+\w+|def\s+\w+|struct\.\w+)[^\n]*', '', text)
        return self.clean(text)