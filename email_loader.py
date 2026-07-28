from pathlib import Path
from email import policy
from email.parser import BytesParser

EMAIL_FOLDER = Path("Email_samples")

def load_email(filename):
    """
    Loads both .txt email sample or an actual .eml email.
    """

    file_path = EMAIL_FOLDER / filename

    if filename.lower().endswith(".txt"):
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
        
    elif filename.lower().endswith(".eml"):
        with open(file_path, "rb") as file:
            message = BytesParser(
                policy=policy.default
            ).parse(file)

        return extract_email_text(message)
    
    else:
        raise ValueError(
            "Unsopported file type."
        )
    
def extract_email_text(message):
    """
    Extracts useful information from an .eml message.
    """

    sender = message.get("From", "")
    subject = message.get("Subject", "")

    body = ""

    if message.is_multipart():

        for part in message.walk():

            if part.get_content_type() =="text/plain":
                body += part.get_content()

    else:

        body = message.get_content()

    return (
        f"From: {sender}\n"
        f"Subject: {subject}\n\n"
        f"{body}"
    )  
