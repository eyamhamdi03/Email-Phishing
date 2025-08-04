import joblib
import numpy as np
from scipy.sparse import hstack
from model.preprocessing_mail import preprocess_email
from model.preprocessing_urls import process_url

# Load models and vectorizers
log_model = joblib.load("model/Mail_model.pkl")
vectorizer = joblib.load("model/tfidf_vectorizerMail.pkl")
url_model = joblib.load("model/random_forest_model.pkl")
expected_features = joblib.load("model/urls.pkl")
irrelevant = ['URL', 'Domain', 'TLD', 'PathQuery', 'label']
expected_features = [col for col in expected_features if col not in irrelevant]

feature_descriptions = {
    "URLLength": "Longueur totale de l’URL. Les URL très longues peuvent être suspectes.",
    "DomainLength": "Longueur du nom de domaine. Un domaine très long ou anormal peut être signe de phishing.",
    "CharContinuationRate": "Taux de répétition de caractères consécutifs dans l’URL, pouvant indiquer une obfuscation.",
    "NoOfSubDomain": "Nombre de sous-domaines présents dans l’URL. Trop de sous-domaines peut indiquer une URL trompeuse.",
    "HasObfuscation": "Indique si des techniques d’obfuscation (ex: encodage, substitution de caractères) sont détectées dans l’URL.",
    "LetterRatioInURL": "Proportion de lettres alphabétiques dans l’URL. Une faible proportion peut être suspecte.",
    "NoOfDegitsInURL": "Nombre de chiffres présents dans l’URL, un nombre élevé peut indiquer une tentative d’obfuscation.",
    "NoOfEqualsInURL": "Nombre de signes '=' dans l’URL, souvent utilisés dans les paramètres, peuvent être suspects.",
    "NoOfQMarkInURL": "Nombre de points d’interrogation '?' dans l’URL, utilisés pour les requêtes, un nombre inhabituel peut être suspect.",
    "NoOfAmpersandInURL": "Nombre de signes '&' dans l’URL, utilisés pour séparer les paramètres, trop peut indiquer une URL complexe.",
    "NoOfOtherSpecialCharsInURL": "Nombre d’autres caractères spéciaux (ex: %, $, #, etc.) dans l’URL, qui peuvent signaler une URL malveillante.",
    "SpacialCharRatioInURL": "Ratio de caractères spéciaux sur la longueur totale de l’URL.",
    "IsHTTPS": "Indique si l’URL utilise HTTPS (protocole sécurisé). L’absence de HTTPS peut être un signe de phishing.",
    "Pay": "Indicateur binaire si des mots liés au paiement sont présents dans l’URL (ex: 'pay', 'billing').",
    "HasHyphenInDomain": "Présence de tirets '-' dans le nom de domaine, parfois utilisés dans les domaines frauduleux.",
    "HasSpecialCharInDomain": "Présence de caractères spéciaux dans le domaine, ce qui peut être suspect.",
    "CountDots": "Nombre total de points '.' dans l’URL, souvent liés au nombre de sous-domaines ou sous-chemins.",
    "Login": "Indique si le mot 'login' apparaît dans l’URL, un signal fréquent dans les URLs de phishing.",
    "Update": "Indique si le mot 'update' apparaît dans l’URL, souvent utilisé dans les tentatives de phishing pour inciter à agir.",
    "SuspiciousTLD": "Indique si le domaine de premier niveau (TLD) est considéré comme suspect ou peu commun.",
    "PathLength": "Longueur du chemin (path) dans l’URL après le domaine.",
    "SuspiciousDomain": "Indicateur si le domaine correspond à une liste noire ou est suspect.",
    "TLD_encoded": "Version encodée ou catégorisation du TLD.",
    "HasHomoglyphs": "Présence de caractères homoglyphes (caractères ressemblant à d'autres, ex: 'о' cyrillique vs 'o' latin).",
    "NumHomoglyphs": "Nombre de caractères homoglyphes détectés dans le domaine.",
    "SuspiciousCount": "Compte total d’éléments suspects détectés dans l’URL.",
    "EndsWithExecutable": "Indique si l’URL se termine par une extension exécutable (ex: .exe), signe probable de malware.",
    "DomainEntropyClass": "Classe d’entropie du domaine, mesure la complexité ou aléatoire du nom (plus élevée = plus suspect).",
    "HasBase64": "Indique si la chaîne contient de l’encodage Base64, souvent utilisé pour cacher des données.",
    "TokenCount": "Nombre de 'tokens' ou segments dans l’URL (ex: parties séparées par '/')."
}


# Thresholds
URL_STRONG_THRESHOLD = 0.7
URL_MID_THRESHOLD = 0.4
EMAIL_THRESHOLD = 0.6
ALPHA = 0.5

def analyze_email(subject, body):
    # --- EMAIL ANALYSIS ---
    cleaned_text, suspicious, has_url, has_attachment, has_html, word_count, length, urls = preprocess_email(subject, body)
    vect = vectorizer.transform([cleaned_text])
    meta_features = np.array([[has_url, has_html, has_attachment, suspicious, length, word_count, len(urls)]])
    X_email = hstack([vect, meta_features])
    email_proba = log_model.predict_proba(X_email)[0][1]

    # --- URL ANALYSIS ---
    link_probs = []
    for url in urls:
        df = process_url(url)
        df = df[[col for col in expected_features if col in df.columns]]
        df = df.loc[:,~df.columns.duplicated()]

        if df.shape[1] == len(expected_features):
            proba = url_model.predict_proba(df)[0][1]
            link_probs.append(proba)
            print(f"URL: {url}")
            print(f"Colonnes dans df: {list(df.columns)}")
            print(f"Colonnes attendues: {expected_features}")
            print(f"Nombre colonnes df: {df.shape[1]}, attendu: {len(expected_features)}")

    max_link_proba = max(link_probs) if link_probs else 0

    # --- DECISION LOGIC ---
    if any(p > URL_STRONG_THRESHOLD for p in link_probs):
        verdict = "FRAUDULEUX"
        final_score = max_link_proba
        final_prediction = 1

    elif any(URL_MID_THRESHOLD <= p <= URL_STRONG_THRESHOLD for p in link_probs):
        final_score = ALPHA * email_proba + (1 - ALPHA) * max_link_proba
        if final_score >= 0.6:
            verdict = "FRAUDULEUX"
            final_prediction = 1
        elif final_score <= 0.4:
            verdict = "LÉGITIME"
            final_prediction = 0
        else:
            verdict = "SUSPECT (à vérifier manuellement)"
            final_prediction = -1

    else:
        final_score = email_proba
        if final_score > EMAIL_THRESHOLD:
            verdict = "FRAUDULEUX"
            final_prediction = 1
        else:
            verdict = "LÉGITIME"
            final_prediction = 0

    return {
        "email_proba": email_proba,
        "max_link_proba": max_link_proba,
        "final_score": final_score,
        "final_prediction": final_prediction,
        "verdict": verdict,
        "urls": urls,
        "link_probs": [float(p) for p in link_probs]
    }
def generate_report(results):
    report_lines = []

    report_lines.append("=== Rapport d'analyse ===")
    report_lines.append(f"Probabilité phishing du mail (modèle contenu) : {results['email_proba']:.4f}")
    report_lines.append(f"Nombre d'URLs détectées dans le mail            : {len(results['urls'])}")

    if results['urls']:
        report_lines.append("Scores individuels des URLs détectées :")
        for i, (url, score) in enumerate(zip(results['urls'], results['link_probs']), start=1):
            report_lines.append(f"  {i}. {url} -> Score phishing : {score:.4f}")
    else:
        report_lines.append("Aucune URL détectée dans le mail.")

    if results['final_prediction'] == 1:
        if results['max_link_proba'] > 0.7:
            report_lines.append("\nLa prédiction de phishing est principalement due à une ou plusieurs URLs malveillantes détectées.")
        else:
            report_lines.append("\nLa prédiction de phishing est principalement due au contenu du mail.")

    elif results['final_prediction'] == 0:
        report_lines.append("\nLe mail est considéré comme légitime.")

    else:
        report_lines.append("\nLe mail est suspect et nécessite une vérification manuelle.")

    if hasattr(url_model, "feature_importances_"):
        report_lines.append("\nCaractéristiques URL les plus importantes indiquant un phishing (Les caractéristiques sur lesquels notre modèle s'est basé) :")
        importances = url_model.feature_importances_
        top_idx = importances.argsort()[-5:][::-1]
        top_features = [expected_features[i] for i in top_idx]
        top_scores = importances[top_idx]
        for f, s in zip(top_features, top_scores):
            description = feature_descriptions.get(f, "TLD")
            report_lines.append(f"  - {f}: importance {s:.4f} — {description}")

    return "\n".join(report_lines)

if __name__ == "__main__":
    subject = "Important: Update Your Account"
    body = """
    Dear user,
    Please update your account immediately by visiting http://malicious.example.com/login.
    Thank you.
    """

    results = analyze_email(subject, body)
    
    print("=== Email Analysis ===")
    print(f"Email phishing probability     : {results['email_proba']:.4f}")
    print(f"Strongest URL phishing prob.   : {results['max_link_proba']:.4f}")
    print(f"Combined phishing score        : {results['final_score']:.4f}")
    print(f"Verdict                        : {results['verdict']}")
    print(f"URLs detected in email         : {results['urls']}")
    print(f"Individual URL scores          : {results['link_probs']}")
    print(generate_report(results))