import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

from ml.naive_bayes import train_model



def main():

    model, vectorizer, X_test, y_test = train_model()

    predictions = model.predict(X_test)

    print("=" * 40)
    print("NAIVE BAYES MODEL EVALUATION")
    print("=" * 40)

    accuracy = accuracy_score(y_test, predictions)

    print(f"\nAccuracy: {accuracy * 100:.2f}%")

    print("\nClassification Report")
    print("=" * 40)

    print(classification_report(y_test, predictions))

    print("\nConfusion Matrix")
    print("=" * 40)

    print(confusion_matrix(y_test, predictions))

if __name__ == "__main__":
    main()