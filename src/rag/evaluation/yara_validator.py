"""YARA Rule structural validator."""
import re


def validate(rule_text: str) -> dict:
    rule          = rule_text.lower()
    has_rule      = bool(re.search(r'\brule\b\s+\w+', rule))
    has_strings   = "strings:"   in rule
    has_condition = "condition:" in rule
    has_meta      = "meta:"      in rule
    has_braces    = "{" in rule and "}" in rule
    has_nocase    = "nocase"     in rule
    has_filesize  = "filesize"   in rule
    num_strings   = len(re.findall(r'\$\w+', rule_text))

    score = (int(has_rule)      * 0.30 +
             int(has_strings)   * 0.25 +
             int(has_condition) * 0.25 +
             int(has_meta)      * 0.10 +
             int(has_braces)    * 0.10)

    return {
        "is_valid"     : has_rule and has_strings and has_condition and has_braces,
        "has_rule"     : has_rule,
        "has_strings"  : has_strings,
        "has_condition": has_condition,
        "has_meta"     : has_meta,
        "has_braces"   : has_braces,
        "num_strings"  : num_strings,
        "has_nocase"   : has_nocase,
        "has_filesize" : has_filesize,
        "syntax_score" : round(score, 4),
    }
