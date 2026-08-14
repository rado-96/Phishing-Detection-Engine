import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from hybrid.hybrid_engine import HybridEngine


print("=" * 40)
print("HYBRID ENGINE TEST")
print("=" * 40)


engine = HybridEngine()


rule_result = {
    "classification": "PHISHING",
    "confidence": 53,
    "risk_level": "HIGH"
}

ml_result = {
    "prediction": "phishing",
    "confidence": 62.3,
    "probabilities": {
        "legitimate": 37.7,
        "phishing": 62.3
    }
}

result = engine.analyse(
    rule_result,
    ml_result
)


print("\nHybrid Result")
print("-" * 40)

print(
    f"Classification: {result['classification']}"
)

print(
    f"Confidence: {result['confidence']}%"
)

print(
    f"Rule Confidence: {result['rule_analysis']['confidence']}%"
)

print(
    f"ML Confidence: {result['ml_analysis']['confidence']}%"
)