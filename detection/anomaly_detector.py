import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self, model_path="models/saved_models/iso_forest.pkl"):
        self.model_path = model_path
        self.model = None

    def train_synthetic(self):
        """Train IsolationForest on synthetic random data"""
        print("[AnomalyDetector] Training synthetic model...")
        # Generate random normal data
        X_normal = np.random.normal(0, 1, (1000, 5))
        # Generate anomalies
        X_anomaly = np.random.uniform(5, 10, (50, 5))
        X_train = np.vstack([X_normal, X_anomaly])

        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.model.fit(X_train)

        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print(f"[AnomalyDetector] Model trained and saved -> {self.model_path}")

    def load_model(self):
        """Load pre-trained model from disk"""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model not found: {self.model_path}. Run --mode train first.")
        self.model = joblib.load(self.model_path)
        print(f"[AnomalyDetector] Loaded model -> {self.model_path}")
        return self.model

    def predict(self, features):
        """Predict if features are anomaly (-1) or normal (1)"""
        if not self.model:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        return self.model.predict([features])[0]

    def anomaly_score(self, features):
        """Return anomaly score (lower = more normal, higher = more anomalous)"""
        if not self.model:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        return -self.model.score_samples([features])[0]
