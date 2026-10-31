import re

PATTERNS = {
    "email_address":r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "possible_openai_key":r"\bsk-[A-Za-z0-9_-]{16,}\b",
    "possible_google_key":r"\bAIza[A-Za-z0-9_-]{20,}\b",
    "private_key_header":r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "possible_aws_access_key":r"\bAKIA[0-9A-Z]{16}\b",
    "password_assignment":r"(?i)\b(password|passwd|secret|token)\s*[:=]\s*[^\s,;]{6,}"
}
HIGH_RISK = {"possible_openai_key","possible_google_key","private_key_header","possible_aws_access_key","password_assignment"}

def inspect_and_redact(text):
    result = text
    categories = []
    blocked = False
    for category, pattern in PATTERNS.items():
        if re.search(pattern,result,re.I):
            categories.append(category)
            if category in HIGH_RISK:
                blocked = True
            else:
                result = re.sub(pattern,"[REDACTED]",result,flags=re.I)
    return {"text":"" if blocked else result,"blocked":blocked,"categories":categories}
