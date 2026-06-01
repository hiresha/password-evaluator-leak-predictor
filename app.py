from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import requests
import math

# FLASK APPLICATION INITIALISATION
app = Flask(__name__)  # CREATE FLASK APP INSTANCE
CORS(app)              # ALLOWS FRONTEND TO CALL API WITHOUT BROWSER BLOCKING

# LOAD TRAINED MODEL + VECTORISER
model = joblib.load("best_logistic_regression_model.pkl")
tfidf = joblib.load("tfidf_vectorizer.pkl")

HIBP_URL = "https://api.pwnedpasswords.com/range/"      # HIBP API ENDPOINT


@app.route("/predict", methods=["POST"])
def predict():

    # GET PASSWORD FROM INCOMING JSON
    data = request.get_json()
    password = data.get("password") if data else None
    prefix = data.get("prefix")
    suffix = data.get("suffix")

    if not password:
        return jsonify({"error": "Password is required"}), 400
    if not prefix or not suffix:
        return jsonify({"error": "prefix and suffix are required for leak detection"}), 400

    # FEATURE EXTRACTION
    password_tfidf = tfidf.transform([password])

    # MODEL PREDICTION (CLASS & PROBABILITIES)
    prediction = model.predict(password_tfidf)[0]
    probabilities = model.predict_proba(password_tfidf)[0].tolist()

    # LEAK DETECTION (HIBP API)
    # SEND ONLY PREFIX FOR SECURITY
    response = requests.get(HIBP_URL + prefix)
    leaked = False
    leak_count = 0

    if response.status_code == 200:
        lines = response.text.splitlines()
        for line in lines:
            hash_suffix, count = line.split(":")
            if hash_suffix.strip().upper() == suffix.strip().upper():
                leaked = True
                leak_count = int(count)
                break

    # ADJUST PASSWORD STRENGTH BASED ON LEAK ANALYSIS
    adjusted_strength = int(prediction)
    if leaked:
        if leak_count > 1_000_000:
            adjusted_strength = 0
        elif leak_count > 10_000:
            adjusted_strength = max(0, adjusted_strength - 2)
        elif leak_count > 100:
            adjusted_strength = max(0, adjusted_strength - 1)

    # ENTROPY CALCULATION

    def password_entropy(password):
        charset = 0
        if any(c.islower() for c in password):
            charset += 26
        if any(c.isupper() for c in password):
            charset += 26
        if any(c.isdigit() for c in password):
            charset += 10
        if any(not c.isalnum() for c in password):
            charset += 32
        if charset == 0:
            return 0
        # H = L. LOG2(N)
        return round(len(password) * math.log2(charset), 2)

    # GENERATE SUGGESTIONS
    def suggest_improvements(password, leaked, leak_count, entropy):
        suggestions = []
        if leaked:
            suggestions.append(
                f"This password has been leaked {leak_count:,} times. Choose a completely new one.")
        if len(password) < 12:
            suggestions.append("Increase length to at least 12 characters")
        if entropy < 50:
            suggestions.append(
                "Entropy is low. Use a mix of character types for unpredictability.")
        if not any(c.isupper() for c in password):
            suggestions.append("Add uppercase letters")
        if not any(c.isdigit() for c in password):
            suggestions.append("Include numbers.")
        if not any(not c.isalnum() for c in password):
            suggestions.append("Include special symbols")

        if not suggestions:
            suggestions.append(
                "This password looks strong. Consider using a password manager to generate unique ones.")
        return suggestions[:3]      # RETURN TOP 3 SUGGESTIONS ONLY

    entropy = password_entropy(password)
    improvements = suggest_improvements(password, leaked, leak_count, entropy)

    # BUILDING FINAL RESPONSE
    response = {
        "strength_class": adjusted_strength,
        "probabilities": probabilities,
        "leaked": leaked,
        "leak_count": leak_count,
        "entropy": entropy,
        "suggestions": improvements
    }

    return jsonify(response), 200


# RUNNING THE FLASK APP
# 0.0.0.0 ALLOWS ACCESS FOR ANY DEVICE (USED FOR TESTING)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
