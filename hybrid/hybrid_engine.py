class HybridEngine:
    """
    Combines the Rule-Based detection results with the Machine Learning predictions
    into one final phishing assessment.
    """

    def __init__(
        self,
        rule_weight=0.7,
        ml_weight=0.3
    ):
        """
        Initialises the hybrid scoring system.

        Rule-Based detection receives 70% importance.
        Machine Learning prediction receives 30% improtance.
        """

        self.rule_weight = rule_weight
        self.ml_weight = ml_weight

    def calculate_hybrid_confidence(
            self,
            rule_confidence,
            ml_confidence
    ):
        """
        Calculates final confidence using weighted scoring.

        The formula is as follows:

            (Rule Confidence * Rule Weight) + (ML Confidence * ML Weight)
        """

        hybrid_confidence = (
            (rule_confidence * self.rule_weight) + (ml_confidence * self.ml_weight)
        )

        return round(
            hybrid_confidence,
            2
        )

    def classify(
        self,
        hybrid_confidence
    ):
        """
        Determines the final classification.
        """

        if hybrid_confidence >= 50:
            return "PHISHING"

        else:
            return "LEGITIMATE"

    def analyse(
        self,
        rule_result,
        ml_result
    ):
        """
        Performs complete hybrid analysis.
        """

        hybrid_confidence = self.calculate_hybrid_confidence(
            rule_result["confidence"],
            ml_result["confidence"]
        )

        classification = self.classify(
            hybrid_confidence
        )

        return {
            "classification": classification,
            "confidence": hybrid_confidence,
            "rule_analysis": rule_result,
            "ml_analysis": ml_result
        }