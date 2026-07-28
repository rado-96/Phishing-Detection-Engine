from config import (
    LEGITIMATE_MAX,
    SUSPICIOUS_MAX,
    HIGH_RISK_MIN,
    CRITICAL_RISK_MIN,
    MAX_SCORE,
)

def calculate_total_score(results):
    """
    Calculates the total risk score from all analysis modules.

    Args:
        results (dict): Dictionary containing all analysis scores.

    Returns
        int: Total risk score.
    """

    total = (
        results["keyword_score"] +
        results["url_score"] +
        results["urgency_score"] +
        results["sender_score"]
    )

    return total

def calculate_confidence(total_score):
    """
    Calculates confidence based on the maximum possible score.
    """
    confidence = (total_score / MAX_SCORE) * 100

    if confidence > 100:
        confidence = 100

    return round(confidence)

def classify_email(total_score):
    """
    Classifies the email based on its total score.

    Args:
        total_score (int): Combined score from all analysis modules.

    Returns:
        str: Email classification
    """

    if total_score <= LEGITIMATE_MAX:
        return "LEGITIMATE"

    elif total_score <= SUSPICIOUS_MAX:
        return "SUSPICIOUS"
    
    return "PHISHING"

def determine_risk_level(confidence):
    """
    Determines the risk level based on confidence score.
    """

    if confidence <= 25:
        return "LOW"
    
    elif confidence <= 50:
        return "MEDIUM"
    
    elif confidence <= 75:
        return "HIGH"
    
    return "CRITICAL"

def generate_recommendation(risk_level):
    """
    Generates a recommendation note based on the risk level.
    """

    if risk_level == "LOW":
        return (
            "No significant phishing indicators were detected.\n"
            "No immediate action is required."
        )
    
    elif risk_level == "MEDIUM":
        return (
            "CAUTION!\n"
            "Verify the sender before clicking links or opening attachments."
        )
    
    elif risk_level == "HIGH":
        return (
            "Multiple phishing indicators detected!\n"
            "Avoid interacting with this email."
        )
    
    elif risk_level == "CRITICAL":
        return (
        "High probability phishing attack detected!\n"
        "Delete the email immediately!\n"
        "Do not click links, open attachments, or provide any personal or financial information!\n"
    ) 