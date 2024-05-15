#!/usr/bin/env python3

import pickle
import pandas as pd
import re
from urllib.parse import urlparse



filename = 'xgboost_model.pkl'


def extract_features(url):
    features = {}

    # UsingIP
    features['UsingIP'] = -1 if re.match(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", url) else 1

    # LongURL
    features['LongURL'] = -1 if len(url) > 75 else 1

    # Symbol@
    features['Symbol@'] = -1 if '@' in url else 1

    # Redirecting//
    features['Redirecting//'] = -1 if '//' in url else 1

    # PrefixSuffix-
    features['PrefixSuffix-'] = -1 if '-' in url else 1

    # SubDomains
    features['SubDomains'] = -1 if len(re.findall(r"\.", url)) > 1 else 1

    # HTTPS
    features['HTTPS'] = -1 if 'https' not in url else 1

    # NonStdPort
    features['NonStdPort'] = -1 if ":" in url and not url.endswith(":80") and not url.endswith(":443") else 1

    # HTTPSDomainURL
    features['HTTPSDomainURL'] = -1 if not re.match(r"https://[a-zA-Z0-9.-]*", url) else 1

    # RequestURL
    features['RequestURL'] = -1  # Assuming this feature is not available for user-entered URLs

    # AnchorURL
    features['AnchorURL'] = -1 if "#" in url else 1

    # LinksInScriptTags
    features['LinksInScriptTags'] = -1 if "<script>" in url else 1

    # ServerFormHandler
    features['ServerFormHandler'] = -1 if "action=" in url else 1

    # InfoEmail
    features['InfoEmail'] = -1 if "github.io" in url else 1

    # AbnormalURL
    features['AbnormalURL'] = -1 if any(substring in url for substring in [';', '&&', '||','.xyz','telegram.']) else 1

    # WebsiteForwarding
    features['WebsiteForwarding'] = -1 if "URL=" in url else 1

    # StatusBarCust
    features['StatusBarCust'] = -1 if has_custom_status_bar(url) else 1

    # DisableRightClick
    features['DisableRightClick'] = -1 if "oncontextmenu" in url else 1

    # UsingPopupWindow
    features['UsingPopupWindow'] = -1 if "window.open" in url else 1

    # IframeRedirection
    features['IframeRedirection'] = -1 if "<iframe" in url else 1

    return pd.DataFrame([features])

# Function to check if the URL contains JavaScript code that customizes the status bar text
def has_custom_status_bar(url):
    return bool(re.search(r"onmouseover\s*=\s*\"window\.status", url))


def predict_phish(url):
    """Predict the legitimacy of the URL"""
    try:
        with open(filename, 'rb') as f:
            model = pickle.load(f)
    except Exception as e:
        print("Error loading the model:", e)
    url_features = extract_features(url)
    predictions = model.predict(url_features)

    prediction_result = 'Legitimate' if predictions[0] == 1 else 'Phishing'
    
    return prediction_result

  