import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
import tldextract
import joblib
from sklearn.preprocessing import LabelEncoder

# Charger modèles préentraînés
tfidf = joblib.load("model/tfidf_urls.pkl")
tld_encoder = joblib.load("model/tld_encoder.pkl")

KEYWORDS = ['login',  'update',  'pay']
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "buzz", "top", "work", "click"}

HOMOGLYPHS_MAP = {'0': 'o', '1': 'l', '3': 'e', '@': 'a', '$': 's', '5': 's', '9': 'g', '6': 'b', '|': 'i', '!': 'i'}

def char_continuation_length(url):
    if not url:
        return 0.0
    # Find all sequences of the same character repeated >=2
    sequences = re.findall(r'(.)\1+', url)

    # Find all runs with their length
    runs = re.findall(r'(.)\1+', url)

    matched = re.finditer(r'(.)\1+', url)
    total_run_length = sum(len(m.group()) for m in matched)

    return total_run_length

def has_obfuscation(url):
    hex_encodings = re.findall(r'%[0-9a-fA-F]{2}', url)
    count_hex = len(hex_encodings)
    count_at = url.count('@')

    total_obfuscated = count_hex + count_at

    has_obfuscation = int(total_obfuscated > 0)

    return pd.Series(has_obfuscation)
def extract_url_parts(url):
    cleaned_url = url.strip().rstrip(".")

    ext = tldextract.extract(url)
    domain = ext.domain
    tld = ext.suffix
    subdomain = ext.subdomain
    no_of_subdomains = subdomain.count('.') + 1 if subdomain else 0
    return pd.Series([domain, tld, no_of_subdomains])
def contains_homoglyph(domain):
  return int(any(char in domain for char in HOMOGLYPHS_MAP))

def count_homoglyphs(domain):
    return sum(domain.count(char) for char in HOMOGLYPHS_MAP)

def count_dots(url):
    try:
        return url.count('.')
    except:
        return 0


def add_url_domain_features(df):
    """
    Ajoute au DataFrame :
    - HasHyphenInDomain : 1 si le domaine contient un '-', sinon 0
    - HasSpecialCharInDomain : 1 si le domaine contient un caractère autre qu'une lettre, sinon 0
    - CountDots : nombre de '.' dans l'URL
    """
    df = df.copy()
    df['HasHyphenInDomain'] = df['Domain'].str.contains('-', regex=False).astype(int)
    df['HasSpecialCharInDomain'] = df['Domain'].str.contains(r'[^a-zA-Z]', regex=True).astype(int)
    df['CountDots'] = df['URL'].apply(count_dots)

    return df

def shannon_entropy(s):
    if not s:
        return 0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * np.log2(p) for p in probs)

def is_suspicious_tld(tld):
    return int(tld in SUSPICIOUS_TLDS)

def check_suspecious(keywords , urls):
  for kw in keywords:
    col_name = f'{kw.capitalize()}'
    urls[col_name] = urls['URL'].str.lower().str.contains(kw).astype(int)
  return urls

def count_suspicious(urls):
    """
    For each URL, counts how many suspicious keywords appear in it.
    Adds a new column 'SuspiciousCount' with the result.
    """
    urls['SuspiciousCount'] = urls['URL'].str.lower().apply(
        lambda url: sum(kw in url for kw in KEYWORDS)
    )
    return urls

def get_path_length(url):
    try:
        path = urlparse(url).path
        return len(path)
    except:
        return 0

def add_all_url_features(url):
    domain, tld, no_of_subdomains = extract_url_parts(url)

    df = pd.DataFrame({
        'URL': [url],
        'Domain': [domain],
        'TLD': [tld],
        'NoOfSubDomain': [no_of_subdomains]
    })
    df = add_url_domain_features(df)
    df = check_suspecious(KEYWORDS, df)
    df['SuspiciousTLD'] = df['TLD'].apply(is_suspicious_tld)
    df['PathLength'] = df['URL'].apply(get_path_length)
    df['DomainEntropy'] = df['Domain'].apply(shannon_entropy)
    df['SuspiciousDomain'] = df['DomainEntropy'].apply(lambda x: 1 if x > 3.5 else 0)
    df['CountDots'] = df['URL'].apply(count_dots)
    df['HasObfuscation'] = df['URL'].apply(has_obfuscation)
    try:
        df['TLD_encoded'] = tld_encoder.transform(df['TLD'])
    except ValueError:
        known_classes = list(tld_encoder.classes_)
        df['TLD_encoded'] = df['TLD'].apply(lambda x: tld_encoder.transform([x])[0] if x in known_classes else -1)
    df["HasHomoglyphs"] = df['Domain'].apply(contains_homoglyph)
    df["NumHomoglyphs"] = df['Domain'].apply(count_homoglyphs)
    df['URLLength']=df['URL'].apply(len)
    df['DomainLength']=df['Domain'].apply(len)
    df['IsHTTPS'] =df['URL'].str.lower().str.startswith('https://').astype(int)
    df['CharContinuationRate'] = df['URL'].apply(char_continuation_length)

    df['CharContinuationRate'] = df['CharContinuationRate'] / df['URLLength'].replace(0, 1)
    df['NoOfEqualsInURL']=df['URL'].str.count('=')

    df['NoOfQMarkInURL'] =df['URL'].str.count('\?')

    df['NoOfAmpersandInURL'] = df['URL'].str.count('&')
    special_chars = r'[@%~#\^*\[\]\{\}|\\<>]'
    df['NoOfOtherSpecialCharsInURL'] =  df['URL'].str.count(special_chars)
    df['TotalSpecialChars'] = df['NoOfQMarkInURL'] + df['NoOfAmpersandInURL'] + df['NoOfOtherSpecialCharsInURL']
    df['SpacialCharRatioInURL'] = df['TotalSpecialChars'] / df['URLLength'].replace(0, 1)
    df = df.drop(columns=['TotalSpecialChars'], errors='ignore')

    df['NoOfLettersInURL'] =df['URL'].str.count(r'[A-Za-z]')
    df['LetterRatioInURL'] =  df['NoOfLettersInURL'] /df['URLLength'].replace(0, 1)
    df.drop(columns=['NoOfLettersInURL'], inplace=True, errors='ignore')
    df['NoOfDegitsInURL'] =df['URL'].str.count(r'\d')

    df['DegitRatioInURL'] =df['NoOfDegitsInURL'] /df['URLLength'].replace(0, 1)
    df = count_suspicious(df)

    return df

def categorize_entropy(ent):
    if ent < 3.5:
        return 0
    elif ent < 4.5:
        return 1
    else:
        return 2

def has_base64(s):
  return bool(re.search(r'(?:[A-Za-z0-9+/]{4}){3,}', s))

def count_tokens(s):
  return len(re.split(r'[/&=?._-]+', s))

def get_path_query(url):
  try:
    parsed = urlparse(url)
    return parsed.path + '?' + parsed.query if parsed.query else parsed.path
  except:
    return ''

def process_url(url):
    urls=add_all_url_features(url)
    urls['EndsWithExecutable'] = urls['URL'].str.endswith(('.exe', '.php', '.bat', '.scr'))
    urls.drop(columns=[
    'DegitRatioInURL',
], inplace=True)
    urls['EndsWithExecutable'] = urls['EndsWithExecutable'].astype(int)
    urls["PathQuery"] = urls["URL"].apply(get_path_query)
    urls["HasBase64"] = urls["PathQuery"].apply(has_base64)
    urls["TokenCount"] = urls["PathQuery"].apply(count_tokens)
    
    urls['DomainEntropyClass'] = urls['DomainEntropy'].apply(categorize_entropy)
    urls.drop(columns=['DomainEntropy'], inplace=True)

    if 'PathQuery' in urls.columns and urls['PathQuery'].notna().all():
        tfidf_matrix = tfidf.transform(urls['PathQuery'])
        tfidf_df = pd.DataFrame(tfidf_matrix.toarray(), columns=[f'TFIDF_{i}' for i in range(tfidf_matrix.shape[1])])
        urls = pd.concat([urls.reset_index(drop=True), tfidf_df.reset_index(drop=True)], axis=1)
    else:
        n_features = tfidf.max_features or len(tfidf.get_feature_names_out())
        for i in range(n_features):
            urls[f'TFIDF_{i}'] = 0

    urls.drop(columns=[ 'URL', 'Domain', 'TLD','PathQuery'],inplace=True)
    return urls