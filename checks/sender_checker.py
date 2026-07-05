import re
from difflib import SequenceMatcher

TRUSTED_DOMAINS = [
    "microsoft.com",
    "paypal.com",
    "amazon.com",
    "google.com",
    "gmail.com",
    "apple.com",
    "icloud.com",
    "outlook.com",
    "yahoo.com"
]

def extract_sender(email_text):
    """
    Extract sender email from the 'From:' field.
    """

    match = re.search(r"From:\s*(\S+)", email_text)

    if match:
        return match.group(1)
    
    return None

def check_sender(email_text):
    """
    Analyses sender for spoofing or impersonation.

    Returns:
        issues (list)
        score (int)
    """

    sender = extract_sender(email_text)

    issues = []
    score = 0

    if not sender:
        return ["No sender found"], 0
    
    domain = sender.split("@")[-1].lower()

    for trusted in TRUSTED_DOMAINS:
        similarity = SequenceMatcher(None, domain, trusted).ratio()

        # Detect near-miss spoofing (typosquatting)
        if similarity > 0.8 and domain != trusted:
            issues.append(f"Possible spoofing of {trusted}: {domain}")
            from config import SENDER_SCORE
            score += SENDER_SCORE

        # Exact match trusted domain
        if domain == trusted:
            issues.append(f"Trusted domain: {domain}")

    return issues, score
