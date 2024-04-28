#!/usr/bin/env python3

import pickle
import pandas as pd
import re



filename = 'xgboost_model.pkl'

def extract_features(url):
    """EXtract necassary features"""
    features = {}
    features['UsingIP'] = 1 if re.match(r"\b(?:[0-9]{1, 3}\.){3}[0-9]{1, 3}\b", url) else 0

    features['LongURL'] = 1 if len(url) > 75 else 0

    features['Symbol@'] =  1 if '@' in url else 0

    features['Redirecting//'] = 1 if '//' in url else 0

    features['PrefixSuffix-'] = 1 if '-' in url else 0

    features['SubDomains'] = len(re.findall(r"\.", url))

    features['HTTPS'] = 1 if 'https' in url else 0

     # Check for prefix/suffix separated by a dash '-'
    features['PrefixSuffix-'] = 1 if '-' in url else 0
    
    # Extract subdomains
    features['SubDomains'] = len(re.findall(r"\.", url))
    
    # Check for HTTPS in URL
    features['HTTPS'] = 1 if 'https' in url else 0
    
    # Extract domain registration length (in months)
    features['DomainRegLen'] = 0  
    
    # Check for presence of favicon
    features['Favicon'] = 0  
    
    # Check for non-standard port (other than 80, 443)
    features['NonStdPort'] = 0  
    
    # Check for HTTPS in domain part of the URL
    features['HTTPSDomainURL'] = 0  
    
    # Check for presence of request URL
    features['RequestURL'] = 0  
    
    # Check for presence of URL of anchor
    features['AnchorURL'] = 0  
    
    # Check for number of links in script tags
    features['LinksInScriptTags'] = 0  
    
    # Check for server form handler
    features['ServerFormHandler'] = 0  
    
    # Check for presence of info email
    features['InfoEmail'] = 0  
    
    # Check for abnormal URL
    features['AbnormalURL'] = 0  
    
    # Check for website forwarding
    features['WebsiteForwarding'] = 0  
    
    # Check for status bar customization
    features['StatusBarCust'] = 0  
    
    # Check for disabling right click
    features['DisableRightClick'] = 0  
    
    # Check for using popup window
    features['UsingPopupWindow'] = 0  
    
    # Check for iframe redirection
    features['IframeRedirection'] = 0  
    
    # Extract age of domain (in months)
    features['AgeofDomain'] = 0  
    
    # Check for DNS recording
    features['DNSRecording'] = 0  
    
    # Extract website traffic (based on rank)
    features['WebsiteTraffic'] = 0  
    
    # Extract page rank
    features['PageRank'] = 0  
    
    # Extract Google index
    features['GoogleIndex'] = 0  
    
    # Extract number of links pointing to the page
    features['LinksPointingToPage'] = 0  
    
    # Extract stats report
    features['StatsReport'] = 0  
    
    
    return pd.DataFrame([features])


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

  