import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from email_loader import load_email
from ml.naive_bayes import NaiveBayesDetector

print("=" * 40)
print("PREDICT EMAIL TEST")
print("=" * 40)


# Load existing phishing email sample
email = load_email("phishing/phishing_1.txt")


print("\nEmail analysed:")
print("-" * 40)
print(email[:500])
print("-" * 40)


# Create Naive Bayes detector
detector = NaiveBayesDetector()


# Predict email
result = detector.predict(email)


print("\nPrediction")
print("-" * 40)

print(f"Prediction : {result['prediction']}")
print(f"Confidence : {result['confidence']}%")


print("\nProbabilities")
print("-" * 40)

print(
    f"Legitimate : {result['probabilities']['legitimate']}%"
)

print(
    f"Phishing   : {result['probabilities']['phishing']}%"
)