# retrain_model.py
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

# Your domain feature extractor function (same 18-feature logic)
from feature_extraction import extract_full_features  # if it's in another file
# OR paste the full extract_full_features() code here directly if needed

# Load labeled dataset
data = pd.read_csv("full_dataset.csv")  # Replace with your combined benign + malicious domain dataset

# Extract features
features_df = data["domain"].apply(extract_full_features).apply(pd.Series)
X = features_df
y = data["label"]

# Train model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Save model and extractor
joblib.dump(clf, "phishing_detector.pkl")
with open("feature_extractor.pkl", "wb") as f:
    pickle.dump(extract_full_features, f)

print("✅ Model retrained and saved as phishing_detector.pkl")