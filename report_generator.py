from pathlib import Path
from datetime import datetime

REPORT_FOLDER = Path("reports")

def generate_security_summary(
        rule_result,
        ml_result,
        hybrid_result
):
    """
    Generates a dynamic summary based on the final
    classification and analysis results.
    """

    classification = hybrid_result["classification"]
    analysis_results = rule_result["scores"]

    keyword_count = len(analysis_results["keywords"])
    url_count = len(analysis_results["urls"])
    urgency_count = len(analysis_results["urgency"])
    sender_results = analysis_results["sender"]

    ml_prediction = ml_result["prediction"]
    ml_confidence = ml_result["confidence"]
    hybrid_confidence = hybrid_result["confidence"]

    summary = []

    # =========================================================
    # PHISHING CLASSIFICATION
    # =========================================================

    if classification == "PHISHING":

        summary.append(
            "The analysed email has been classified as PHISHING."
        )

        indicators = []

        if keyword_count > 0:
            indicators.append(
                f"{keyword_count} suspicious keyword indicator(s)"
            )

        if url_count > 0:
            indicators.append(
                f"{url_count} suspicious URL indicator(s)"
            )

        if urgency_count > 0:
            indicators.append(
                f"{urgency_count} urgency indicator(s)"
            )

        # Only count sender findings as suspicious when they
        # actually describe a sender-related security concern.
        suspicious_sender_count = 0

        for sender_issue in sender_results:
            sender_issue_lower = sender_issue.lower()

            if (
                "spoof" in sender_issue_lower
                or "suspicious" in sender_issue_lower
                or "mismatch" in sender_issue_lower
                or "invalid" in sender_issue_lower
                or "untrusted" in sender_issue_lower
            ):
                suspicious_sender_count += 1

        if suspicious_sender_count > 0:
            indicators.append(
                f"{suspicious_sender_count} sender-related indicator(s)"
            )

        if indicators:
            summary.append(
                "The Rule-Based detection engine identified "
                + ", ".join(indicators)
                + "."
            )
        else:
            summary.append(
                "The Rule-Based detection engine did not identify "
                "any significant predefined security indicators."
            )

        summary.append(
            f"The Automated Threat Detection model classified "
            f"the email as {ml_prediction.upper()} with a confidence "
            f"of {ml_confidence}%."
        )

        summary.append(
            "Both detection methods support the phishing classification."
        )


    # =========================================================
    # LEGITIMATE CLASSIFICATION
    # =========================================================

    else:

        summary.append(
            "The analysed email has been classified as LEGITIMATE."
        )

        indicators = []

        if keyword_count > 0:
            indicators.append(
                f"{keyword_count} suspicious keyword indicator(s)"
            )

        if url_count > 0:
            indicators.append(
                f"{url_count} suspicious URL indicator(s)"
            )

        if urgency_count > 0:
            indicators.append(
                f"{urgency_count} urgency indicator(s)"
            )

        # Determine whether sender findings are suspicious
        # or represent positive/trusted evidence.
        suspicious_sender_count = 0
        trusted_sender_count = 0

        for sender_issue in sender_results:

            sender_issue_lower = sender_issue.lower()

            if (
                "spoof" in sender_issue_lower
                or "suspicious" in sender_issue_lower
                or "mismatch" in sender_issue_lower
                or "invalid" in sender_issue_lower
                or "untrusted" in sender_issue_lower
            ):
                suspicious_sender_count += 1

            elif (
                "trusted" in sender_issue_lower
                or "verified" in sender_issue_lower
                or "valid" in sender_issue_lower
            ):
                trusted_sender_count += 1

        if suspicious_sender_count > 0:
            indicators.append(
                f"{suspicious_sender_count} sender-related indicator(s)"
            )

        if indicators:
            summary.append(
                "The Rule-Based detection engine identified "
                + ", ".join(indicators)
                + ", but the overall Rule-Based assessment "
                "remained within the legitimate classification."
            )
        else:

            if trusted_sender_count > 0:

                summary.append(
                    "The Rule-Based detection engine did not identify "
                    "any significant predefined phishing indicators. "
                    "The sender analysis also provided positive evidence "
                    "by identifying a trusted domain."
                )

            else:

                summary.append(
                    "The Rule-Based detection engine did not identify "
                    "any significant predefined security indicators."
                )

        summary.append(
            f"The Automated Threat Detection model classified "
            f"the email as {ml_prediction.upper()} with a confidence "
            f"of {ml_confidence}%."
        )

        summary.append(
            "Both detection methods support the legitimate classification."
        )

    # Hybrid explanation applies to both classifications
    summary.append(
        "The Hybrid Detection Engine combines the results from "
        "both detection methods using the configured weighting "
        f"system, producing a final hybrid confidence score "
        f"of {hybrid_confidence}%."
    )

    return "\n\n".join(summary)


def generate_report(
        filename,
        rule_result,
        ml_result,
        hybrid_result,
        ):
    """
    Generates a text report containing the combined results of
    the Rule-Based, Machine Learning and Hybrid analysis.
    """

    REPORT_FOLDER.mkdir(exist_ok=True)

    safe_name = Path(filename).stem
    report_name = f"{safe_name}_report.txt"
    report_path = REPORT_FOLDER / report_name

    # Report generation date and time
    generated_at = datetime.now()
    report_date = generated_at.strftime("%d/%m/%Y")
    report_time = generated_at.strftime("%H:%M")

    # Extract Rule-Based analysis results
    analysis_results = rule_result["scores"]
    total_score = rule_result["total_score"]
    classification = rule_result["classification"]
    confidence = rule_result["confidence"]
    risk_level = rule_result["risk_level"]
    recommendation = rule_result["recommendation"]

    # Extract Machine Learning detection results
    ml_prediction = ml_result["prediction"]
    ml_confidence = ml_result["confidence"]

    legitimate_probability = (
        ml_result["probabilities"]["legitimate"]
    )

    phishing_probability = (
        ml_result["probabilities"]["phishing"]
    )

    # Extract Hybrid results
    hybrid_classification = hybrid_result["classification"]
    hybrid_confidence = hybrid_result["confidence"]

    # Generate dynamic security summary
    security_summary = generate_security_summary(
        rule_result,
        ml_result,
        hybrid_result
    )
    
    # Report Summary
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("=" * 30 + "\n")
        report.write("RESULTS REPORT\n")
        report.write("=" * 30 + "\n\n")

        report.write(f"Analysed File : {filename}\n")
        report.write(f"Report Date   : {report_date}\n")
        report.write(f"Report Time   : {report_time}\n\n")

    # Keyword analysis result
        report.write("-" * 30 + "\n")
        report.write("KEYWORD ANALYSIS\n")
        report.write("-" * 30 + "\n")

        if analysis_results["keywords"]:
            for keyword in analysis_results["keywords"]:
                report.write(f"• {keyword}\n")
        else:
            report.write("No suspicious keywords detected.\n")

        report.write(f"\nScore: {analysis_results['keyword_score']}\n\n")

    # URL analysis result
        report.write("-" * 30 + "\n")
        report.write("URL ANALYSIS\n")
        report.write("-" * 30 + "\n")        

        if analysis_results["urls"]:
            for url in analysis_results["urls"]:
                report.write(f"• {url}\n")
        else:
            report.write("No URLs detected.\n")

        report.write(f"\nScore: {analysis_results['url_score']}\n\n")

    # Urgency analysis result
        report.write("-" * 30 + "\n")
        report.write("URGENCY ANALYSIS\n")
        report.write("-" * 30 + "\n")

        if analysis_results["urgency"]:
            for item in analysis_results["urgency"]:
                report.write(f"• {item}\n")
        else:
            report.write("No urgency indicators detected.\n")

        report.write(f"\nScore: {analysis_results['urgency_score']}\n\n")

    # Sender analysis result
        report.write("-" * 30 + "\n")
        report.write("SENDER ANALYSIS\n")
        report.write("-" * 30 + "\n")

        if analysis_results["sender"]:
            for issue in analysis_results["sender"]:
                report.write(f"• {issue}\n")
        else:
            report.write("No sender issues detected.\n")

        report.write(f"\nScore: {analysis_results['sender_score']}\n\n")

    # Rule-Based Analysis
        report.write("=" * 30 + "\n")
        report.write("RULE-BASED DETECTION\n")
        report.write("=" * 30 + "\n\n")

        report.write(f"Rule-Based Classification: {classification}\n")
        report.write(f"Rule-Based Total Score   : {total_score}\n")
        report.write(f"Rule-Based Confidence    : {confidence}%\n")
        report.write(f"Risk Level               : {risk_level}\n\n")

        # Rule-Based calculation explained
        report.write("How the result was calculated\n")
        report.write("-" * 30 + "\n")

        report.write(
            "The Rule-Based engine calculates the total risk by combining\n"
            "the scores generated by the keyword, URL, urgency and sender\n"
            "analysis modules.\n\n"
        )

        report.write(
            "Each detected indicator contributes a predefined number of points\n"
            "to the overall score. Higher scores indicate a greater presence of\n"
            "known phishing characteristics.\n\n"
        )

        report.write(
            "The final confidence percentage is derived from the total risk score\n"
            "and represents the strength of the Rule-Based assessment.\n\n"
        )

        report.write(
            "The resulting confidence is then used to determine the associated\n"
            "risk level.\n\n"
        )

    # Machine Learning Analysis
        report.write("=" * 30 + "\n")
        report.write("AUTOMATED THREAT DETECTION\n")
        report.write("=" * 30 + "\n\n")

        report.write("Model: Multinomial Naive Bayes\n\n")
        report.write(f"Prediction   : " f"{ml_prediction}\n")
        report.write(f"Confidence   : " f"{ml_confidence}%\n\n")

        report.write(f"Prediction Probabilities\n")
        report.write("-" * 30 + "\n")

        report.write(f"Legitimate   : " f"{legitimate_probability}%\n")
        report.write(f"Phishing     : " f"{phishing_probability}%\n\n")

        # Machine Learning Detection calculation explanation
        report.write("How the result was calculated\n")
        report.write("-" * 30 + "\n")

        report.write(
            "The email is converted into numerical TF-IDF features using "
            "the same\n"
            "vectorizer created during model training.\n\n"
        )

        report.write(
            "The trained classifier evaluates these features and "
            "calculates the\n"
            "probability that the email belongs to each class.\n\n"
        )

        report.write(
            "The class with the highest probability becomes the "
            "predicted\n"
            "classification, while the probability is used as the "
            "prediction\n"
            "confidence.\n\n"
        )

    # Hybrid Security Assessment
        report.write("=" * 30 + "\n")
        report.write("HYBRID SECURITY ASSESSMENT\n")
        report.write("=" * 30 + "\n\n")

        report.write(f"Final Classification           : {hybrid_classification}\n")
        report.write(f"Hybrid Confidence              : {hybrid_confidence}%\n")
        report.write(f"Rule-Based Confidence          : {confidence}%\n")
        report.write(f"Machine Learning Confidence    : {ml_confidence}%\n\n")

        # Hybrid calculation explanation
        report.write("How the result was calculated\n")
        report.write("-" * 30 + "\n")

        report.write(
            "The current configuration assigns 70% weight to the "
            "Rule-Based\n"
            "assessment and 30% weight to the Automated Threat detection "
            "model.\n\n"
        )

        report.write(
            "This produces a single hybrid confidence score while preserving\n"
            "the results of both individual detection methods.\n\n"
        )

    # Final result
        report.write("=" * 30 + "\n")
        report.write("REPORT OUTCOME\n")
        report.write("=" * 30 + "\n")

        report.write(f"Rule-Based Classification       : {classification}\n")
        report.write(f"Automated Threat Detection      : {ml_prediction.upper()}\n")
        report.write(f"Final Classification            : {hybrid_classification}\n\n")
        report.write(f"Rule-Based Confidence           : {confidence}%\n")
        report.write(f"Automated Threat Confidence     : {ml_confidence}%\n")
        report.write(f"Hybrid Confidence               : {hybrid_confidence}%\n")
        report.write(f"Risk Level                      : {risk_level}\n\n")

        report.write(
            f"{security_summary}\n\n"
        )

    # Recommendation
        report.write("Recommendation\n")
        report.write("-" * 30 + "\n")
        report.write(f"{recommendation}\n")

    return report_path