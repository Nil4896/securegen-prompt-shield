import re

PATTERNS = {
    "instruction_override": [r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions", r"override\s+(the\s+)?system\s+prompt", r"forget\s+(all\s+)?your\s+rules"],
    "system_prompt_extraction": [r"(reveal|show|print|repeat|output|tell me)\s+(your\s+)?(hidden\s+)?(system prompt|system instructions|secret instructions)", r"what\s+are\s+your\s+system\s+instructions"],
    "jailbreak_language": [r"act\s+as\s+an\s+unrestricted", r"bypass\s+(your\s+)?safety", r"developer\s+mode\s+enabled", r"pretend\s+you\s+have\s+no\s+rules"],
    "credential_request": [r"(reveal|print|show|expose)\s+(all\s+)?(passwords|api keys|access tokens|credentials)"]
}

def scan_input(text):
    reasons = [name for name, patterns in PATTERNS.items() if any(re.search(p, text, re.I) for p in patterns)]
    if len(text) > 8000:
        reasons.append("unusually_long_input")
    return {"risk":"high" if reasons else "low", "reasons":reasons, "hard_block":"unusually_long_input" in reasons, "rule_detected":bool(reasons)}
