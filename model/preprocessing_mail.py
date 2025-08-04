# preprocessing_utils.py

import re
import unidecode
import spacy
import numpy as np
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

nlp = spacy.load("en_core_web_sm")

def remove_html(text):
    soup = BeautifulSoup(str(text), "html.parser")
    return soup.get_text()

def remove_urls(text):
    text = str(text).lower()
    text = re.sub(r'https?://\S+|www\.\S+', '', text)
    text = re.sub(r'(http|https)\s*[:]\s*/\s*/\s*\S+', '', text)
    text = re.sub(r'www\s*(\.\s*\w+)+', '', text)
    text = re.sub(r'\bhttp\b', '', text)
    text = re.sub(r'\b\w+\s*\.\s*(com|fr|net|org|info|biz|edu|gov)\b', '', text)
    return text

def remove_attached_files(text):
    pattern = r'\b[\w\s-]+ ?\. ?(pdf|docx?|xlsx?|zip|rar|exe|js|scr|vbs|bat|7z)\b'
    text = re.sub(r'\S+@\S+', '', text)
    text = re.sub(pattern, '', text, flags=re.IGNORECASE)
    return text
def contains_url(text):
    text = str(text).lower()
    pattern = r'https?://\S+|www\.\S+|(http|https)\s*[:]\s*/\s*/\s*\S+|\b\w+\s*\.\s*(com|fr|net|org|info|biz|edu|gov)\b'
    return int(bool(re.search(pattern, text)))

def has_attached_file(text):
    pattern = r'\b[\w\s-]+ ?\. ?(pdf|docx?|xlsx?|zip|rar|exe|js|scr|vbs|bat|7z)\b'
    return int(bool(re.search(pattern, str(text), flags=re.IGNORECASE)))

def has_html(text):
    return int('html' in str(text).lower())

def lemmatize(text):
    doc = nlp(str(text))
    return ' '.join([token.lemma_ for token in doc])

def text_proc(text):
    text = re.sub(r'\d', '', text)
    text = re.sub(r'[\n\r\\]+', ' ', text)
    text = re.sub(r'[^\w\s]', '', text)

    words = text.lower().split()
    words = [w for w in words if w not in ENGLISH_STOP_WORDS]
    text = ' '.join(words)

    text = unidecode.unidecode(text)
    return text

# ----------------------------
# Détection de contenu suspect
# ----------------------------

suspicious = [
    # General salutations
    "dear user",
    "dear client",
    "dear customer",
    "dear member",
    "dear friend",
    "hello user",
    # Urgency-related words
    "urgent",
    "right now",
    "now",
    "immediately",
    "as soon as possible",
    "act now",
    "limited time",
    "limited",
    "offer",
    "last chance",
    "expires soon",
    "take action",
    "verify immediately",
    "your access is restricted",
    "subscription",
    "subscriptionid","spam"

    # Phishing-related phrases
    "free",
    "free coupon",
    "click here",
    "login now",
    "update your information",
    "security alert",
    "verify your identity",
    "confirm your password",
    "verify your account",
    "win a prize",
    "prize","password",
    "exclusive",
    "download the document",
    "check your statement",
    "reset your password",
    "security verification",
    "urgent action required",
    "spam"

    # Malware-related terms
    "trojan",
    "trojanspy",
    "trojandownloader",
    "trojanqqpass",
    "trojanmybot",
    "trojanpcclient",
    "trojanhupigon",
    "trojanmezziacy",
    "keylogger",
    "ransomware",
    "spyware",
    "malicious", "software",
    "virus" ,"detected",
    "infected",
    "threat removal",
    "threat",
    "security"," scan",
    "quarantine report",
    "dangerous file",
    "suspicious attachment"
]


def contains_suspicious_phrases(text):
    text_lower = text.lower()
    for phrase in suspicious:
        if re.search(r'\b' + re.escape(phrase) + r'\b', text_lower):
            return 1
    return 0

def preprocess_email(subject, body):
    """
    Prétraite un email à partir du sujet et du corps.
    
    Étapes :
    - Concatène sujet + corps
    - Extrait toutes les URLs avant nettoyage
    - Nettoie le texte (HTML, fichiers, ponctuation...)
    - Extrait des indicateurs (suspicious phrases, urls, pièces jointes, html, etc.)

    Retourne :
    - cleaned: texte nettoyé pour vectorisation
    - suspicious: 0/1 si phrase suspecte présente
    - contains_url: 0/1 si URL détectée
    - has_attached_file: 0/1 si fichier détecté
    - has_html: 0/1 si contenu HTML
    - word_count: nombre de mots dans le texte nettoyé
    - length: nombre de caractères dans le texte original
    - urls: liste des URLs extraites avant suppression
    """
    subject = str(subject)
    body = str(body)
    full_text = subject + " " + body
    original = full_text.lower()

    # 1. Extraction des URLs avant tout nettoyage
    url_pattern = r'https?://\S+|www\.\S+|(?:http|https)\s*[:]\s*/\s*/\s*\S+|\b\w+\s*\.\s*(?:com|fr|net|org|info|biz|edu|gov)\b'
    found_urls = re.findall(url_pattern, original)
    found_urls = [url.rstrip('.,;!?') for url in found_urls]

    # 2. Nettoyage du texte
    cleaned = remove_html(full_text)
    cleaned = remove_urls(cleaned)
    cleaned = remove_attached_files(cleaned)
    cleaned = text_proc(cleaned)
    cleaned = lemmatize(cleaned)

    suspicious_flag = contains_suspicious_phrases(full_text)
    url_flag = contains_url(full_text)
    attached_flag = has_attached_file(full_text)
    html_flag = has_html(full_text)

    word_count = len(cleaned.split())
    length = len(full_text)

    return cleaned, suspicious_flag, url_flag, attached_flag, html_flag, word_count, length, found_urls
