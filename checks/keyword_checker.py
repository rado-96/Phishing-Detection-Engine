import re

PHISHING_KEYWORDS = [
    "urgent",
    "verify",
    "account suspended",
    "immediately",
    "click here",
    "password",
    "login",
    "bank",
    "confirm",
    "security alert",
    "action required",
]


def check_keywords(email_text):
    """
    Scans email for phishing-related keywords.
    Returns:
        found_keywords (list)
        score (int)
    """


    email_lower = email_text.lower()

    found_keywords = []
    score = 0

    for keyword in PHISHING_KEYWORDS:
        pattern = r"\b" + re.escape(keyword) + r"\b"
        if re.search(pattern, email_lower):
            found_keywords.append(keyword)
            from config import KEYWORD_SCORE
            score += KEYWORD_SCORE

    return found_keywords, score