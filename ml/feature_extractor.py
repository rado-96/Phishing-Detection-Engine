from sklearn.feature_extraction.text import TfidfVectorizer

def create_features(emails):
    """
    Converts email text into numerical TF-IDF features.

    Args:
        emails: List of email text samples

    Returns:
        vectorizer: Trained TF-IDF vectorized.

        features: Numerical representation of emails.
    """

    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english"
    )

    features = vectorizer.fit_transform(emails)

    return vectorizer, features