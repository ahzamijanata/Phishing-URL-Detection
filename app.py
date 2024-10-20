import tensorflow as tf
from tensorflow.keras.models import load_model
from flask import Flask, request, render_template, jsonify
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd
import joblib
import warnings
warnings.filterwarnings('ignore')
from featurextract import feature_extract

app = Flask(__name__)

# Load the pre-trained model
model = load_model('model/ModelD2.h5')
model.summary()

scaler = joblib.load('src/scaler_gabungan.pkl')
total_features = 97

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Get the URL from the form
        url = request.form["url"]
        
        # Extract features from the URL
        obj = feature_extract(url)
        features = obj.getFeaturesList()
        print(f"URL: {url}")  # Debug: Print input URL
        print(f"Features: {features}")  # Debug: Print extracted features
                
        # Convert to numpy array
        features = np.array(features)
        
        # Identify numeric and boolean features
        #boolean_indices = [38, 39, 94, 96, 98, 106, 108, 109, 110]     # indices for boolean features
        boolean_indices = [25, 26, 81, 83, 85, 93, 95, 96, 97]
        numeric_indices = [i for i in range(total_features) if i not in boolean_indices]  # indices for numeric features
        
        non_boolean_features = features[numeric_indices].reshape(1, -1)
        boolean_features = features[boolean_indices].reshape(1, -1)
        
        # Standardize numeric features
        scaled_non_boolean_features = scaler.transform(non_boolean_features)
        
        # Combine scaled numeric and boolean features
        combined_features = np.hstack((scaled_non_boolean_features, boolean_features))
        print(f"Combined features shape: {combined_features.shape}")  # Debug: Print combined shape
        print(f"Combined features: {combined_features}")  # Debug: Print extracted features

        # Make a prediction
        y_pred = model.predict(combined_features)
        print(f"Prediction: {y_pred}")  # Debug: Print raw prediction output
        
        # Extract phishing probability
        y_pro_phishing = y_pred[0, 0]  # Phishing probability
        y_pro_non_phishing = 1 - y_pro_phishing  # Non-phishing probability
        print(f"Phishing Probability: {y_pro_phishing}, Non-Phishing Probability: {y_pro_non_phishing}")  # Debug: Print probabilities
        
        # Determine if the URL is phishing or safe
        if y_pro_phishing > 0.5:
            pred = f"It is {y_pro_phishing * 100:.2f}% unsafe to go."
        else:
            pred = f"It is {y_pro_non_phishing * 100:.2f}% safe to go."
        
        # Render the template with the prediction
        return render_template('index.html', xx=round(y_pro_non_phishing, 2), url=url, pred=pred)
    
    # Render the initial template
    return render_template("index.html", xx=-1)

@app.route("/API", methods=["POST"])
def check_url():
    try:
        url = request.form["url"]
        obj = feature_extract(url)
        features = obj.getFeaturesList()
        print(f"API Call - URL: {url}")  # Debug: Print input URL
        print(f"API Call - Features: {features}")  # Debug: Print extracted features
        
        features = np.array(features)
        print(f"API Call - Input shape: {features.shape}")  # Debug: Print shape of the input

        boolean_indices = [25, 26, 81, 83, 85, 93, 95, 96, 97]     # indices for boolean features
        numeric_indices = [i for i in range(total_features) if i not in boolean_indices]  # indices for numeric features
        
        non_boolean_features = features[numeric_indices].reshape(1, -1)
        boolean_features = features[boolean_indices].reshape(1, -1)
        
        # Standardize numeric features
        scaled_non_boolean_features = scaler.transform(non_boolean_features)
        
        # Combine scaled numeric and boolean features
        combined_features = np.hstack((scaled_non_boolean_features, boolean_features))
        print(f"Combined features shape: {combined_features.shape}")  # Debug: Print combined shape
        print(f"Combined features: {combined_features}")  # Debug: Print extracted features
        
        y_pred = model.predict(combined_features)
        print(f"API Call - Prediction: {y_pred}")  # Debug: Print raw prediction output

        # Extract phishing probability
        y_pro_phishing = y_pred[0, 0]  # Phishing probability
        y_pro_non_phishing = 1 - y_pro_phishing  # Non-phishing probability
        print(f"Phishing Probability: {y_pro_phishing}, Non-Phishing Probability: {y_pro_non_phishing}")  # Debug: Print probabilities

        y_pro_phishing = y_pred[0, 0]
        y_pro_non_phishing = 1 - y_pro_phishing
        if y_pro_phishing > 0.5:
            pred = f"It is {y_pro_phishing * 100:.2f}% unsafe to go."
        else:
            pred = f"It is {y_pro_non_phishing * 100:.2f}% safe to go."
        return jsonify({'pred': pred})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'Error occurred'}), 500

if __name__ == "__main__":
    app.run(debug=True)
