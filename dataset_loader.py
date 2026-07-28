from pathlib import Path
from email_loader import load_email

PHISHING_FOLDER = Path("email_samples/phishing")
LEGITIMATE_FOLDER = Path("email_samples/legitimate")

def load_dataset():
    """
    Loads phishing and legitimate emails.

    Returns:
        emails - list of email contents
        labels - list of corresponding labels
    """

    emails = []
    labels = []

    # Load phishing emails
    for file in PHISHING_FOLDER.iterdir():
        if file.is_file():
            email = load_email(f"phishing/{file.name}")

            emails.append(email)
            labels.append("phishing")

    # Load legitimate emails
    for file in LEGITIMATE_FOLDER.iterdir():
        if file.is_file():
            email = load_email(f"legitimate/{file.name}")

            emails.append(email)
            labels.append("legitimate")

    return emails, labels