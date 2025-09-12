# models/anomaly_detector.py
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'saved_models')
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, 'iso_forest.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')

class AnomalyDetector:
    def __init__(self, model=None, scaler=None):
        self.model = model
        self.scaler = scaler

    @staticmethod
    def features_from_df(df):
        # choose numeric features used in training/prediction
        feats = ['packet_count','unique_dst_ports','proto_tcp_ratio','syn_count','avg_pkt_size','total_payload']
        for c in feats:
            if c not in df.columns:
                df[c] = 0
        return df[feats].astype(float)

    def fit(self, df):
        X = self.features_from_df(df).values
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)
        model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42)
        model.fit(Xs)
        self.model = model
        self.scaler = scaler
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        return self

    def load(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            return self
        raise FileNotFoundError("Model or scaler not found. Please train first.")

    def predict_score(self, df):
        # returns anomaly score (higher = more normal in some sklearn versions; we'll normalize)
        X = self.features_from_df(df).values
        Xs = self.scaler.transform(X)
        # decision_function: higher = less abnormal; we invert to produce anomaly score where larger = more anomalous
        scores = - self.model.decision_function(Xs)
        return scores

    def predict_label(self, df, threshold=0.5):
        scores = self.predict_score(df)
        # normalize between 0 and 1
        norm = (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
        labels = (norm >= threshold).astype(int)
        return labels, norm

def train_synthetic_and_save():
    """
    Create synthetic 'normal' traffic features and a few anomalies, then train.
    This is only for demo/run purposes.
    """
    rng = np.random.RandomState(42)
    # normal: packet_count 1-20, unique ports 1-5, tcp ratio ~0.6, syn small
    normals = {
        'packet_count': rng.randint(1, 25, 1000),
        'unique_dst_ports': rng.randint(1, 6, 1000),
        'proto_tcp_ratio': rng.uniform(0.4, 1.0, 1000),
        'syn_count': rng.randint(0, 3, 1000),
        'avg_pkt_size': rng.uniform(60, 800, 1000),
        'total_payload': rng.uniform(0, 4000, 1000)
    }
    df_norm = pd.DataFrame(normals)
    # anomalies
    anoms = {
        'packet_count': rng.randint(200, 1000, 10),
        'unique_dst_ports': rng.randint(30, 100, 10),
        'proto_tcp_ratio': rng.uniform(0.0, 1.0, 10),
        'syn_count': rng.randint(50, 500, 10),
        'avg_pkt_size': rng.uniform(40, 1500, 10),
        'total_payload': rng.uniform(10000, 500000, 10)
    }
    df_anom = pd.DataFrame(anoms)
    df_train = pd.concat([df_norm, df_anom], ignore_index=True)
    detector = AnomalyDetector()
    detector.fit(df_train)
    print("Trained synthetic model and saved to", MODEL_PATH)
    return detector

