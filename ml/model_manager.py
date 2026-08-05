from pathlib import Path
import pickle

MODEL_FOLDER = Path("models")

MODEL_FILE = MODEL_FOLDER / "naive_bayes_model.pkl"

VECTORIZER_FILE = MODEL_FOLDER / "tfidf_vectorizer.pkl"

def save_model(model, vectorizer):
    """
    Saves the trained Naive Bayes model and TF-IDF vectorizer.
    """

    MODEL_FOLDER.mkdir(exist_ok=True)

    with open(MODEL_FILE, "wb") as file:
        pickle.dump(
            model,
            file
        )

    with open(VECTORIZER_FILE, "wb") as file:
        pickle.dump(
            vectorizer,
            file
        )

def load_model():
    """
    Loads the saved Naive Bayes model and TF-IDF vectorizer.
    """

    if not MODEL_FILE.exists() or not VECTORIZER_FILE.exists():
        return None, None

    with open(MODEL_FILE, "rb") as file:
        model = pickle.load(file)

    with open(VECTORIZER_FILE, "rb") as file:
        vectorizer = pickle.load(file)

    return model, vectorizer