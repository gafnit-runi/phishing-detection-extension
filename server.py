from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import pickle

app = Flask(__name__)
CORS(app)

model = joblib.load("phishing_detector.pkl")
from feature_extraction import extract_full_features as extractor

@app.route("/check_url", methods=["POST"])
def check_url():
    domain = request.json.get("domain")
    features = pd.DataFrame([extractor(domain)])
    prediction = model.predict(features)[0]
    return jsonify({"prediction": "phishing" if prediction == 1 else "benign"})

if __name__ == "__main__":
    app.run(port=5000)