from config import LEGITIMATE_MAX, SUSPICIOUS_MAX

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

def classify_email(total_score):
    """
    Classifies the email based on its total score.

    Args:
        total_score (int): Combined score from all analysis modules.

    Returns:
        str: Email classification
    """

    if total_score <= LEGITIMATE_MAX:
        return "Legitimate"

    elif total_score <= SUSPICIOUS_MAX:
        return "Suspicious"
    
    return "Phishing"