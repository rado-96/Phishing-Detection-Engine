"""
Central configuration file for the Phishing Detector engine.

All scoring values and classifications are stored here.

Changing the values here will update the behaviour of the entire program. 
"""

# Module Scores
KEYWORD_SCORE = 2
URL_SCORE = 5
URGENCY_SCORE = 3
SENDER_SCORE = 5

# Classification Tresholds
LEGITIMATE_MAX = 4
SUSPICIOUS_MAX = 9
# 10+ classifies as PHISHING!

# Risk Level Tresholds
HIGH_RISK_MIN = 10
CRITICAL_RISK_MIN = 20

# Maximum Possible Score
MAX_KEYWORDS = 11
MAX_URGENCY = 10
MAX_URLS = 1
MAX_SENDERS = 1

MAX_SCORE = (
    MAX_KEYWORDS * KEYWORD_SCORE +
    MAX_URGENCY * URGENCY_SCORE +
    MAX_URLS * URL_SCORE +
    MAX_SENDERS * SENDER_SCORE
)