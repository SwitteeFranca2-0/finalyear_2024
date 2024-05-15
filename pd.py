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



# def extrac_features(url):
#     """EXtract necassary features"""
#     features = {}
#     # Check for presence of an IP address
#     features['UsingIP'] = 1 if re.match(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", url) else 0
    
#     # Check for long URL (>75 characters)
#     features['LongURL'] = 1 if len(url) > 75 else 0
    
#     # Check for presence of @ symbol
#     features['Symbol@'] = 1 if '@' in url else 0
    
#     # Check for redirection '//'
#     features['Redirecting//'] = 1 if '//' in url else 0
    
#     # Check for prefix/suffix separated by a dash '-'
#     features['PrefixSuffix-'] = 1 if '-' in urlparse(url).netloc else 0
    
#     # Extract subdomains
#     features['SubDomains'] = len(urlparse(url).netloc.split('.')) - 2  # Subtract 2 for domain and top-level domain
    
#     # Check for HTTPS in URL
#     features['HTTPS'] = 1 if 'https' in url else 0
    
#     # Extract domain registration length (in months)
#     try:
#         domain = tldextract.extract(url)
#         if domain.domain and domain.suffix:
#             domain_name = domain.domain + '.' + domain.suffix
#             # Placeholder for domain registration length calculation
#             features['DomainRegLen'] = 0
#         else:
#             features['DomainRegLen'] = 0
#     except Exception as e:
#         features['DomainRegLen'] = 0
    
#     # Check for presence of favicon
#     features['Favicon'] = 1 if 'favicon.ico' in url else 0
    
#     # Check for non-standard port (other than 80, 443)
#     features['NonStdPort'] = 1 if urlparse(url).port not in [80, 443] else 0
    
#     # Check for HTTPS in domain part of the URL
#     features['HTTPSDomainURL'] = 1 if 'https://' in urlparse(url).netloc else 0
    
#     # Check for presence of request URL
#     features['RequestURL'] = 1 if 'request' in url else 0
    
#     # Check for presence of URL of anchor
#     features['AnchorURL'] = 1 if '#' in url else 0
    
#     # Check for number of links in script tags
#     features['LinksInScriptTags'] = 1 if 'src=' in url else 0
    
#     # Check for server form handler
#     features['ServerFormHandler'] = 1 if 'server' in url else 0
    
#     # Check for presence of info email
#     features['InfoEmail'] = 1 if 'mailto:' in url else 0
    
#     # Check for abnormal URL
#     features['AbnormalURL'] = 1 if 'abnormal' in url else 0
    
#     # Check for website forwarding
#     features['WebsiteForwarding'] = 1 if 'forwarding' in url else 0
    
#     # Check for status bar customization
#     features['StatusBarCust'] = 1 if 'statusbar' in url else 0
    
#     # Check for disabling right click
#     features['DisableRightClick'] = 1 if 'rightclick' in url else 0
    
#     # Check for using popup window
#     features['UsingPopupWindow'] = 1 if 'popup' in url else 0
    
#     # Check for iframe redirection
#     features['IframeRedirection'] = 1 if 'iframe' in url else 0
    
#     # Extract age of domain (in months)
#     try:
#         domain = tldextract.extract(url)
#         if domain.domain and domain.suffix:
#             domain_name = domain.domain + '.' + domain.suffix
#             # Placeholder for age of domain calculation
#             features['AgeofDomain'] = 0
#         else:
#             features['AgeofDomain'] = 0
#     except Exception as e:
#         features['AgeofDomain'] = 0
    
#     # Check for DNS recording
#     features['DNSRecording'] = 1 if 'dns' in url else 0
#     for i in range(5):
#         features[f'Feature_{i}'] = 0
   
#     return pd.DataFrame([features])


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

  