"""
Central configuration file for the Phishing Detector engine.

Changing the values here will update the behaviour of the entire program. 
"""

# Module Scores
KEYWORD_SCORE = 2
URL_SCORE = 5
URGENCY_SCORE = 3
SENDER_SCORE = 5

# Risk Tresholds
LEGITIMATE_MAX = 4
SUSPICIOUS_MAX = 9
# 10+ classifies as PHISHING!