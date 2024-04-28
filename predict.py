#!/usr/bin/env python3

import pickle
import pandas as pd
import re


filename = 'xgboost_model.pkl'

try:
    with open(filename, 'rb') as f:
        model = pickle.load(f)
except Exception as e:
    print("Error loading the model:", e)

print('passed')

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

    for i in range(22):
        features[f'Feature_{i}'] = 0
    
    return pd.DataFrame([features])

def predict(url_features):
    """Function that performs the prediction"""
    predictions = model.predict(url_features)

    prediction_result = 'Legitimate' if predictions[0] == 1 else 'Phishing'
    
    return prediction_result



def predict_phish(url):
    """Predict the legitimacy of the URL"""
    try:
        with open(filename, 'rb') as f:
            model = pickle.load(f)
    except Exception as e:
        print("Error loading the model:", e)
    url_features = extract_features(url)
    result = predict(url_features)
    return result

    
print(predict(extract_features('https://www.bodijahmarket.com')))