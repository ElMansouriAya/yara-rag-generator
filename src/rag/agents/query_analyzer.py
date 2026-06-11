"""
QueryAnalyzer Agent — analyzes the user query and extracts metadata.

No LLM required — uses keyword pattern matching on known malware types.
Fast and deterministic.

Output drives RetrievalAgent decisions.
"""

import re

MALWARE_KEYWORDS = {
    "ransomware" : ["ransomware", "encrypt", "ransom", "aes", "shadow", "locked", "bitcoin"],
    "trojan"     : ["trojan", "rat", "remote access", "banker", "credential", "injection"],
    "spyware"    : ["spyware", "screenshot", "monitor", "keylog", "bitblt", "inject"],
    "worm"       : ["worm", "smb", "propagat", "spread", "autorun", "usb", "replicate"],
    "botnet"     : ["botnet", "ddos", "c2", "irc", "flood", "bot", "command and control"],
    "backdoor"   : ["backdoor", "bind shell", "reverse shell", "port", "persist", "dns tunnel"],
    "cryptominer": ["miner", "monero", "xmrig", "stratum", "cpu", "cryptomine"],
    "dropper"    : ["dropper", "download", "payload", "macro", "xor", "obfuscat"],
    "keylogger"  : ["keylogger", "keystroke", "hook", "setwindowshookex", "ftp"],
    "rootkit"    : ["rootkit", "ssdt", "kernel", "hook", "hide process"],
}

# Keywords that suggest sparse retrieval is better
TECHNICAL_TERMS = [
    "aes", "smb", "ssdt", "powershell", "vssadmin", "createremotethread",
    "setwindowshookex", "netushareenum", "xmrig", "stratum", "bitblt",
    "virtualalloc", "shellexecute", "regsetvalueex", "dns", "ftp", "irc",
]


class QueryAnalyzer:
    """
    Analyzes a natural language threat query.

    Returns metadata used by RetrievalAgent to decide:
      - which malware type is described
      - which retriever is most appropriate
      - complexity level of the query
    """

    def analyze(self, query: str) -> dict:
        """
        Analyze a query and return metadata.

        Args:
            query: natural language threat description

        Returns:
            {
                "malware_type"        : str,
                "keywords"            : list[str],
                "complexity"          : "simple" | "complex",
                "has_technical_terms" : bool,
                "suggested_retriever" : "dense" | "sparse" | "hybrid"
            }
        """
        q_lower  = query.lower()
        words    = q_lower.split()

        # ── Detect malware type ──────────────────────────────────────
        malware_type   = "unknown"
        best_score     = 0
        for mtype, kws in MALWARE_KEYWORDS.items():
            score = sum(1 for kw in kws if kw in q_lower)
            if score > best_score:
                best_score   = score
                malware_type = mtype

        # ── Detect technical terms ───────────────────────────────────
        found_technical  = [t for t in TECHNICAL_TERMS if t in q_lower]
        has_technical    = len(found_technical) > 0

        # ── Complexity ───────────────────────────────────────────────
        complexity = "simple" if len(words) <= 8 else "complex"

        # ── Suggest retriever ────────────────────────────────────────
        if has_technical and len(found_technical) >= 2:
            suggested = "sparse"       # many exact keywords → BM25 better
        elif len(words) > 12:
            suggested = "dense"        # long semantic query → FAISS better
        else:
            suggested = "hybrid"       # default: best of both

        return {
            "malware_type"       : malware_type,
            "keywords"           : found_technical or words[:5],
            "complexity"         : complexity,
            "has_technical_terms": has_technical,
            "suggested_retriever": suggested,
        }
