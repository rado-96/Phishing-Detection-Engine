import re

def check_urls(email_text):
    """
    Finds URLs in an email and assigns a basic risk score.

    Returns:
        urls (list)
        score (int)
    """

    # Find URLs starting with 'http://' or 'https://'
    urls = re.findall(r'https?://\S+', email_text)

    score = 0

    if urls:
        from config import URL_SCORE
        score= len(urls) * URL_SCORE

    return urls, score