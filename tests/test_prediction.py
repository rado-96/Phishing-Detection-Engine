import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from ml.naive_bayes import train_model
from email_loader import load_email

print("=" * 40)
print("NAIVE BAYES PREDICTION TEST")
print("=" * 40)


# Train the model
model, vectorizer, X_test, y_test = train_model()


# Load an email for prediction
email = load_email("phishing/phishing_1.txt")


# Convert email into TF-IDF features
email_features = vectorizer.transform([email])


# Make prediction
prediction = model.predict(email_features)
probabilities = model.predict_proba(email_features)

print("\nModel Prediction:")
print(prediction[0])

print("\nPrediction Probabilities:")

classes = model.classes_

for label, probability in zip(classes, probabilities[0]):
    print(f"{label.capitalize():12}: {probability * 100:.2f}%")
