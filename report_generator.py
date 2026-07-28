from pathlib import Path

REPORT_FOLDER = Path("reports")

def generate_report(
        filename, 
        analysis_results, 
        total_score, 
        classification,
        confidence,
        risk_level,
        recommendation,
        ):
    """
    Generates a text report containing the results of the phishing analysis.
    """

    REPORT_FOLDER.mkdir(exist_ok=True)

    safe_name = Path(filename).stem
    report_name = f"{safe_name}_report.txt"
    report_path = REPORT_FOLDER / report_name

    print(f"DEBUG REPORT PATH: {report_path}")
    
    # Report Summary
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("=" * 30 + "\n")
        report.write("RESULTS REPORT\n")
        report.write("=" * 30 + "\n\n")

        report.write(f"Analysed File : {filename}\n")
        report.write(f"Classification: {classification}\n")
        report.write(f"Total Score   : {total_score}\n\n")

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

    # Final result
        report.write("=" * 30 + "\n")
        report.write("REPORT OUTCOME\n")
        report.write("=" * 30 + "\n")

        report.write(f"Total Score   : {total_score}\n")
        report.write(f"Classification: {classification}\n")
        report.write(f"Confidence    : {confidence}%\n")
        report.write(f"Risk Level    : {risk_level}\n\n")

        report.write("Recommendation\n")
        report.write("-" * 30 + "\n")
        report.write(f"{recommendation}\n")

    return report_path