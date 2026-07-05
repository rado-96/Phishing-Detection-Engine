import re

URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "action required",
    "24 hours",
    "account suspended",
    "final warning",
    "respond now",
    "verify immediately",
    "limited time",
    "failure to comply"
]

def check_urgency(email_text):
    """
    Detects urgency-based social engineering language.

    Returns:
        found urgency (list)
        score (int)
    """

    email_lower = email_text.lower()

    found_urgency = []
    score = 0

    for phrase in URGENCY_KEYWORDS:
        pattern = r"\b" + re.escape(phrase) + r"\b"

        if re.search(pattern, email_lower):
            found_urgency.append(phrase)
            from config import URGENCY_SCORE
            score += URGENCY_SCORE

    return found_urgency, score