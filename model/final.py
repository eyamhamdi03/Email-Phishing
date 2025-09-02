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
MID_THRESHOLD = 0.4
EMAIL_THRESHOLD = 0.6
ALPHA = 0.5

def analyze_email(subject, body):
    # --- EMAIL ANALYSIS ---
    cleaned_text, suspicious, has_url, has_attachment, has_html, word_count, length, urls, reply = preprocess_email(subject, body)
    vect = vectorizer.transform([cleaned_text])
    meta_features = np.array([[has_url, has_html, has_attachment, suspicious, length, word_count, len(urls), reply]])
    X_email = hstack([vect, meta_features])
    email_proba = log_model.predict_proba(X_email)[0][1]

    # --- URL ANALYSIS ---
    link_probs = []
    for url in urls:
        df = process_url(url)
        df = df[[col for col in expected_features if col in df.columns]]
        df = df.loc[:, ~df.columns.duplicated()]

        if df.shape[1] == len(expected_features):
            proba = url_model.predict_proba(df)[0][1]
            link_probs.append(proba)

    url_count = len(link_probs)
    num_phishing_urls = sum(p > 0.6 for p in link_probs)
    has_strong_url = any(p > URL_STRONG_THRESHOLD for p in link_probs)
    has_phishing_url = int(num_phishing_urls > 0)
    phishing_ratio = num_phishing_urls / url_count if url_count > 0 else 0
    max_url_score = max(link_probs) if link_probs else 0
    mean_url_score = float(np.mean(link_probs)) if link_probs else 0
    std_url_score = float(np.std(link_probs)) if len(link_probs) > 1 else 0

    # --- DECISION LOGIC ---
    if has_phishing_url and has_strong_url:
        final_prediction = 1
        final_score = max_url_score
        verdict = "FRAUDULEUX"
    else:
        final_score = ALPHA * email_proba + (1 - ALPHA) * (phishing_ratio + max_url_score) / 2
        if final_score >= EMAIL_THRESHOLD:
            final_prediction = 1
            verdict = "FRAUDULEUX"
        elif final_score <= MID_THRESHOLD:
            final_prediction = 0
            verdict = "LÉGITIME"
        else:
            final_prediction = -1
            verdict = "SUSPECT"

    return {
        "email_proba": email_proba,
        "max_link_proba": max_url_score,
        "final_score": final_score,
        "final_prediction": final_prediction,
        "verdict": verdict,
        "urls": urls,
        "link_probs": [float(p) for p in link_probs],
        "meta_features": {
            "has_url": has_url,
            "has_html": has_html,
            "has_attachment": has_attachment,
            "suspicious": suspicious,
            "length": length,
            "word_count": word_count,
            "number_of_urls": url_count,
            "reply": reply
        },
        "url_features": {
            "url_count": url_count,
            "num_phishing_urls": num_phishing_urls,
            "has_phishing_url": has_phishing_url,
            "phishing_ratio": phishing_ratio,
            "max_url_score": max_url_score,
            "mean_url_score": mean_url_score,
            "std_url_score": std_url_score
        }
    }

def generate_final(results):
    report_lines = []
    report_lines.append("=== Rapport d'analyse global ===")
    report_lines.append(f"Probabilité phishing du mail (modèle contenu) : {results['email_proba']:.4f}")
    report_lines.append(f"Nombre d'URLs détectées dans le mail            : {len(results['urls'])}")

    if results['urls']:
        report_lines.append("Scores individuels des URLs détectées :")
        for i, (url, score) in enumerate(zip(results['urls'], results['link_probs']), start=1):
            report_lines.append(f"  {i}. {url} -> Score phishing : {score:.4f}")
    else:
        report_lines.append("Aucune URL détectée dans le mail.")

    if results['final_prediction'] == 1:
        if results['url_features']['has_phishing_url']:
            report_lines.append("\nLa prédiction de phishing est principalement due à une ou plusieurs URLs malveillantes détectées.")
        else:
            report_lines.append("\nLa prédiction de phishing est principalement due au contenu du mail.")
    elif results['final_prediction'] == 0:
        report_lines.append("\nLe mail est considéré comme légitime.")
    else:
        report_lines.append("\nLe mail est suspect et nécessite une vérification manuelle.")

    report_lines.append("\n=== Détails des caractéristiques du mail analysé ===")
    meta = results.get('meta_features', {})
    meta_descriptions = {
        'has_url': "Présence d'URLs dans le mail",
        'has_html': "Contenu HTML détecté",
        'has_attachment': "Pièces jointes détectées",
        'suspicious': "Phrases suspectes détectées",
        'length': "Longueur du mail en caractères",
        'word_count': "Nombre de mots",
        'number_of_urls': "Nombre d'URLs extraites",
        'reply': "Indicateur de réponse"
    }

    for key, desc in meta_descriptions.items():
        val = meta.get(key, 'Inconnu')
        if key in ['length', 'word_count', 'number_of_urls']:
            val_str = str(val)
        else:
            val_str = "Oui" if val == 1 else "Non"
        report_lines.append(f" - {desc} : {val_str}")
    
    all_features = list(vectorizer.get_feature_names_out())

    coefs = log_model.coef_[0]
    feature_coefs = dict(zip(all_features, coefs))

    top_pos = sorted(feature_coefs.items(), key=lambda x: x[1], reverse=True)[:10]
    top_neg = sorted(feature_coefs.items(), key=lambda x: x[1])[:10]

    if results['final_prediction'] == 1 or results['final_prediction'] == -1:
        report_lines.append("Caractéristiques les plus indicatives d'un phishing:")
        for feat, val in top_pos:
            line = f" - {feat}"
            if desc:
                line += f" ({desc})"
            report_lines.append(line)

    else:
        report_lines.append("\nCaractéristiques les plus indicatives d'un mail légitime :")
        for feat, val in top_neg:
            line = f" - {feat}"
            if desc:
                line += f" ({desc})"
            report_lines.append(line)

    if len(results['urls']) >0:

        report_lines.append("\n=== Statistiques détaillées sur les URLs ===")
        url_stats = results.get("url_features", {})
        report_lines.append(f"Nombre total d'URLs               : {url_stats.get('url_count', 0)}")
        report_lines.append(f"Nombre d'URLs suspectes           : {url_stats.get('num_phishing_urls', 0)}")
        report_lines.append(f"Ratio d’URLs suspectes            : {url_stats.get('phishing_ratio', 0):.2f}")
        report_lines.append(f"Score max d’une URL               : {url_stats.get('max_url_score', 0):.4f}")
        report_lines.append(f"Score moyen des URLs              : {url_stats.get('mean_url_score', 0):.4f}")
        report_lines.append(f"Écart-type des scores des URLs    : {url_stats.get('std_url_score', 0):.4f}")

    if results['urls'] and hasattr(url_model, "feature_importances_"):
        report_lines.append("\nCaractéristiques URL les plus importantes indiquant un phishing :")
        importances = url_model.feature_importances_
        top_idx = importances.argsort()[-5:][::-1]
        top_features = [expected_features[i] for i in top_idx]
        top_scores = importances[top_idx]
        for f, s in zip(top_features, top_scores):
            description = feature_descriptions.get(f, "Description non disponible")
            report_lines.append(f"  - {f}: importance {s:.4f} — {description}")

    return "\n".join(report_lines)
 