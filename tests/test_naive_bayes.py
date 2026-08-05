import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from ml.naive_bayes import train_model

print("=" * 40)
print("NAIVE BAYES TRAINING TEST")
print("=" * 40)

model, vectorizer, X_test, y_test = train_model()

print("\nModel trained successfully!")

print(f"\nNumber of test samples: {len(y_test)}")

print("\nTest labels:")
print(y_test)