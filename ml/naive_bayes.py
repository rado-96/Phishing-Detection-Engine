from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from dataset_loader import load_dataset
from ml.feature_extractor import extract_features

class NaiveBayesDetector:
    """
    Machine Learning engine responsible for training and predicting
    phishing emails using the Multinomial Naive Bayes classifier.
    """

    def __init__(self):
        """
        Creates and trains the Naive Bayes detector.
        """

        self.model = None
        self.vectorizer = None
        self.X_test = None
        self.y_test = None

        self.load_or_train()

    def load_or_train(self):
        """
        Loads an existing model.
        If no model exists, trains a new one.
        """

        from ml.model_manager import load_model

        model, vectorizer = load_model()

        if model is not None:
            self.model = model
            self.vectorizer = vectorizer

            print("Successfully loaded the saved Naive Bayes model.")

        else:
            print("No saved model found. Training a new model...")

            self.train()


    def train(self):
        """
        Trains the Naive Bayes phishing classifier.
        """

        # Load email dataset
        emails, labels = load_dataset()

        # Convert email text into numerical TF-IDF features
        features, vectorizer = extract_features(emails)

        # Split dataset into training and testing data
        X_train, X_test, y_train, y_test = train_test_split(
            features,
            labels,
            test_size=0.2,
            random_state=42
        )

        # Create and train Naive Bayes classifier
        model = MultinomialNB()

        model.fit(
            X_train,
            y_train
        )

        # Store trained components inside the object
        self.model = model
        self.vectorizer = vectorizer
        self.X_test = X_test
        self.y_test = y_test

        from ml.model_manager import save_model

        save_model(
            self.model,
            self.vectorizer
        )

        print("Model saved successfully.")


    def predict(self, email_text):
        """
        Predicts whether an email is phishing or legitimate.

        Args:
            email_text (string):
                Email content to analyse.

        Returns:
            dict:
                Prediction result including confidence
                and class probabilities.
        """

        # Convert email text into TF-IDF features
        features = self.vectorizer.transform(
            [email_text]
        )

        # Predict email classification
        prediction = self.model.predict(features)[0]


        # Calculate prediction probabilities
        probabilities = self.model.predict_proba(features)[0]


        # Match probabilities with class names
        class_probabilities = dict(
            zip(
                self.model.classes_,
                probabilities
            )
        )


        # Confidence is the probability of predicted class
        confidence = (
            class_probabilities[prediction] * 100
        )


        return {
            "prediction": prediction,

            "confidence": round(
                confidence,
                2
            ),

            "probabilities": {

                "legitimate": round(
                    class_probabilities.get(
                        "legitimate",
                        0
                    ) * 100,
                    2
                ),

                "phishing": round(
                    class_probabilities.get(
                        "phishing",
                        0
                    ) * 100,
                    2
                ),
            },
        }