from pathlib import Path
from checks.keyword_checker import check_keywords
from checks.url_checker import check_urls
from checks.urgency_checker import check_urgency
from checks.sender_checker import check_sender
from risk_engine import (
    calculate_total_score,
    calculate_confidence, 
    classify_email,
    determine_risk_level,
    generate_recommendation,
)
from report_generator import generate_report
from email_loader import load_email
from ml.naive_bayes import NaiveBayesDetector
from hybrid.hybrid_engine import HybridEngine


def main():
    print("=" * 50)
    print("     PHISHING EMAIL DETECTOR")
    print("=" * 50)

    filename = input("\nEnter email filename: ")

    try:
        email = load_email(filename)

        import re

        email_cleaned = re.sub(r'https?://\S+', '', email.lower())

        print("\nEmail loaded successfully.\n")

        print("-" * 50)
        print(email)
        print("-" * 50)

        analysis_results = {}

        ml_detector = NaiveBayesDetector()
        hybrid_engine = HybridEngine()

        found_keywords, keyword_score = check_keywords(email_cleaned)
        analysis_results["keywords"] = found_keywords
        analysis_results["keyword_score"] = keyword_score

        print("----- KEYWORD ANALYSIS -----")

        if analysis_results["keywords"]:
            print("Suspicious keywords found:")
            for kw in found_keywords:
                print(f" - {kw}")
        else:
            print("No suspicious keywords found.")

        print(f"\nKeyword Score: {analysis_results['keyword_score']}")

        found_urls, url_score = check_urls(email)
        analysis_results["urls"] = found_urls
        analysis_results["url_score"] = url_score

        print("\n----- URL ANALYSIS -----")

        if analysis_results["urls"]:
            print("URLs detected:")

            for url in analysis_results["urls"]:
                print(f" - {url}")
        else:
            print("No URLs detected.")

        print(f"\nURL Score: {analysis_results['url_score']}")

        found_urgency, urgency_score = check_urgency(email_cleaned)
        analysis_results["urgency"] = found_urgency
        analysis_results["urgency_score"] = urgency_score

        print("\n----- URGENCY ANALYSIS -----")

        if analysis_results["urgency"]:
            print("Urgency indicators found:")
            for item in analysis_results["urgency"]:
                print(f" - {item}")
        else:
            print("No urgency indicators found.")

        print(f"\nUrgency Score: {analysis_results['urgency_score']}")

        sender_issues, sender_score = check_sender(email)
        analysis_results["sender"] = sender_issues
        analysis_results["sender_score"] = sender_score

        print("\n----- SENDER ANALYSIS -----")

        if analysis_results["sender"]:
            for issue in analysis_results["sender"]:
                print(f" - {issue}")
        else:
            print("No sender information found.")

        print(f"\nSender Score: {analysis_results['sender_score']}")

        total_score = calculate_total_score(analysis_results)
        classification = classify_email(total_score)
        confidence = calculate_confidence(total_score)
        risk_level = determine_risk_level(confidence)
        recommendation = generate_recommendation(risk_level)

        rule_result = {
            "classification": classification,
            "confidence": confidence,
            "risk_level": risk_level,
            "recommendation": recommendation,
            "total_score": total_score,
            "scores": analysis_results
        }

        ml_result = ml_detector.predict(email)

        hybrid_result = hybrid_engine.analyse(
            rule_result,
            ml_result
        )

        print("\n" + "=" * 30)
        print("RULE-BASED SUMMARY")
        print("=" * 30)

        print(f"Keyword Score : {analysis_results['keyword_score']}")
        print(f"URL Score     : {analysis_results['url_score']}")
        print(f"Urgency Score : {analysis_results['urgency_score']}")
        print(f"Sender Score  : {analysis_results['sender_score']}")

        print("-" * 30)

        print(f"Total Score    : {total_score}")
        print(f"Classification : {classification}")
        print(f"Confidence     : {confidence}%")
        print(f"Risk Level     : {risk_level}")

        print("\n" + "=" * 30)
        print("MACHINE LEARNING ANALYSIS")
        print("=" * 30)

        print(f"Prediction : {ml_result['prediction']}")
        print(f"Confidence : {ml_result['confidence']}%")

        print("\nProbabilities")
        print("------------------------------")

        print(
            f"Legitimate : "
            f"{ml_result['probabilities']['legitimate']}%"
        )

        print(
            f"Phishing   : "
            f"{ml_result['probabilities']['phishing']}%"
        )

        print("\n" + "=" * 30)
        print("HYBRID SECURITY ASSESSMENT")
        print("=" * 30)

        print(f"Final Classification : "
              f"{hybrid_result['classification']}")

        print(f"Hybrid Confidence    : "
              f"{hybrid_result['confidence']}%")
        
        print(f"Rule Confidence      : "
              f"{hybrid_result['rule_analysis']['confidence']}%")

        print(
            f"ML Confidence        : "
            f"{hybrid_result['ml_analysis']['confidence']}%"
        )

        print("\nRecommendation")
        print("------------------------------")
        print(recommendation)

        report_path = generate_report(
            filename,
            rule_result,
            ml_result,
            hybrid_result,
        )

        print(f"Analysis report has been generated and saved to: {report_path}")

    except FileNotFoundError as error:
        print("\nFile error occured:")
        print(error)

    except Exception as error:
        print(f"\nUnexpected error: {error}")


if __name__ == "__main__":
    main()