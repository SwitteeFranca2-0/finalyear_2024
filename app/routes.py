from flask import Flask, render_template, request, jsonify
from app import app
from predict_legit import predict_phish


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """Endpoint for prediction"""
    data = request.json['url']
    result = predict_phish(data)
    data = {'result': f'{result}'}
    return jsonify(data)



if __name__ == '__main__':
    app.run(debug=True)
