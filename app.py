from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import requests
import math

app = Flask(__name__)  # creates Flask application instance
CORS(app)

# Load the trained model and TF-IDF vectorizer
model = joblib.load("logistic_regression_model.pkl")
tfidf = joblib.load("tfidf_vectorizer.pkl")

HIBP_URL = "https://api.pwnedpasswords.com/range/"


@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Password strength API is running"}), 200


@app.route("/predict", methods=["POST"])  # main API
def predict():
    # """
    # Expects JSON: {
    #  "prefix": "21BD1",
    #  "suffix": "0018A45C4D1DEF81644B54AB7F969B88D65"

    #    }
    # Returns: strength class + probabilities (and later leak info)
    # """
    data = request.get_json()

    # Get the password from the incoming JSON
    password = data.get("password") if data else None
    prefix = data.get("prefix")
    suffix = data.get("suffix")

    # Basic validation
    if not password:
        return jsonify({"error": "Password is required"}), 400

    if not prefix or not suffix:
        return jsonify({"error": "prefix and suffix are required for leak detection"}), 400

    # Transform the password using the same TF-IDF vectorizer used during training
    password_tfidf = tfidf.transform([password])

    # Predict the strength class (0: weak, 1: moderate, 2: strong)
    prediction = model.predict(password_tfidf)[0]

    # Predict class probabilities, e.g. [0.05, 0.10, 0.85]
    probabilities = model.predict_proba(password_tfidf)[0].tolist()

    #################################################################
    # Console logging for initial prediction
    strength_names = {0: "Weak", 1: "Moderate", 2: "Strong"}
    print(f"\n--- Password Strength Analysis ---")
    print(
        f"Initial Prediction: {strength_names.get(int(prediction), 'Unknown')} (Class {int(prediction)})")
    print(
        f"Probabilities: Weak={probabilities[0]:.2%}, Moderate={probabilities[1]:.2%}, Strong={probabilities[2]:.2%}")

    # Leak detection using HIBP
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

    # Adjust strength based on leak severity
    adjusted_strength = int(prediction)

    if leaked:
        if leak_count > 1_000_000:
            adjusted_strength = 0
        elif leak_count > 10_000:
            adjusted_strength = max(0, adjusted_strength - 2)
        elif leak_count > 100:
            adjusted_strength = max(0, adjusted_strength - 1)
        else:
            adjusted_strength = max(0, adjusted_strength - 1)

    # -
    # Console logging for leak detection and adjusted strength
    if leaked:
        print(f"Leaked: Yes ({leak_count:,} occurrences)")
        print(
            f"Adjusted Strength: {strength_names.get(adjusted_strength, 'Unknown')} (Class {adjusted_strength})")
    else:
        print(f"Leaked: No")
        print(
            f"Adjusted Strength: {strength_names.get(adjusted_strength, 'Unknown')} (Class {adjusted_strength}) - No change")
    print(f"-----------------------------------\n")

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
        return round(len(password) * math.log2(charset), 2)

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
        return suggestions[:3]

    entropy = password_entropy(password)
    improvements = suggest_improvements(password, leaked, leak_count, entropy)

    # Build the response
    response = {
        "strength_class": adjusted_strength,
        "probabilities": probabilities,
        "leaked": leaked,
        "leak_count": leak_count,
        "entropy": entropy,
        "suggestions": improvements
    }

    return jsonify(response), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
