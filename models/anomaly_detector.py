# models/anomaly_detector.py
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, "iso_forest.pkl")

HONEYPOT_CSV = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed", "honeypot_attacks.csv")
os.makedirs(os.path.dirname(HONEYPOT_CSV), exist_ok=True)

class AnomalyDetector:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        # min/max of raw anomaly scores (after inversion) observed on training set
        self._min_score = None
        self._max_score = None
        # If model file exists load it
        if os.path.exists(self.model_path):
            try:
                self.load_model()
            except Exception:
                pass

    @staticmethod
    def features_from_df(df: pd.DataFrame) -> pd.DataFrame:
        # features expected by the project
        feats = ['packet_count','unique_dst_ports','proto_tcp_ratio','syn_count','avg_pkt_size','total_payload']
        out = df.copy()
        for c in feats:
            if c not in out.columns:
                out[c] = 0
        return out[feats].astype(float)

    def fit(self, df: pd.DataFrame, n_estimators=200, contamination=0.01, random_state=42):
        """
        Fit scaler + IsolationForest on df (assumed numeric features).
        Also compute training anomaly-score min/max for normalization.
        """
        X = self.features_from_df(df).values
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)

        model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=random_state)
        model.fit(Xs)

        # decision_function: higher = more normal (in sklearn). We invert to make higher = more anomalous.
        raw_scores = -model.decision_function(Xs)
        self._min_score = float(np.min(raw_scores))
        self._max_score = float(np.max(raw_scores))

        self.model = model
        self.scaler = scaler
        # persist
        joblib.dump({"model": self.model, "scaler": self.scaler, "min_score": self._min_score, "max_score": self._max_score}, self.model_path)
        return self

    def save_model(self):
        if self.model is None or self.scaler is None:
            raise RuntimeError("No model to save")
        joblib.dump({"model": self.model, "scaler": self.scaler, "min_score": self._min_score, "max_score": self._max_score}, self.model_path)

    def load_model(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError("Model file not found")
        obj = joblib.load(self.model_path)
        self.model = obj.get("model")
        self.scaler = obj.get("scaler")
        self._min_score = obj.get("min_score")
        self._max_score = obj.get("max_score")
        return self

    def _raw_scores_from_df(self, df: pd.DataFrame):
        X = self.features_from_df(df).values
        Xs = self.scaler.transform(X)
        raw = - self.model.decision_function(Xs)  # higher -> more anomalous
        return raw

    def predict(self, df_or_series):
        """
        Return normalized score in [0,1]. Accepts:
         - pandas.Series (single sample)
         - pandas.DataFrame (single row)
         - dict -> converted
        """
        if self.model is None or self.scaler is None:
            raise RuntimeError("Model not loaded")

        if isinstance(df_or_series, dict):
            df = pd.DataFrame([df_or_series])
        elif isinstance(df_or_series, pd.Series):
            df = pd.DataFrame([df_or_series.to_dict()])
        elif isinstance(df_or_series, pd.DataFrame):
            df = df_or_series
        else:
            # try to coerce
            df = pd.DataFrame([dict(df_or_series)])

        raw = self._raw_scores_from_df(df)
        # Normalize using min/max computed on training
        if self._min_score is None or self._max_score is None or (self._max_score - self._min_score) < 1e-9:
            # fallback min-max across this sample
            rmin = float(np.min(raw))
            rmax = float(np.max(raw))
        else:
            rmin = self._min_score
            rmax = self._max_score
        # map raw to [0,1]
        norm = (raw - rmin) / (rmax - rmin + 1e-12)
        # clip
        norm = np.clip(norm, 0.0, 1.0)
        if norm.shape[0] == 1:
            return float(norm[0])
        return norm

    def add_attack_sample(self, sample: dict):
        """
        Append a single sample (dict of features) to honeypot_attacks.csv.
        sample must use the feature names expected by features_from_df.
        """
        os.makedirs(os.path.dirname(HONEYPOT_CSV), exist_ok=True)
        df = pd.DataFrame([sample])
        header = not os.path.exists(HONEYPOT_CSV)
        df.to_csv(HONEYPOT_CSV, mode="a", index=False, header=header)

    def retrain_with_honeypot(self, honeypot_path: str = HONEYPOT_CSV, normal_count: int = 2000):
        """
        Retrain model using honeypot attacks as anomalies and synthetic normal samples.
        Returns True if retrain occurred.
        """
        # read honeypot data
        if not os.path.exists(honeypot_path):
            return False
        df_anom = pd.read_csv(honeypot_path)
        if df_anom.empty:
            return False

        # create synthetic normals with ranges loosely based on honeypot stats or defaults
        rng = np.random.RandomState(42)
        # heuristics for normal distribution (match features_from_df)
        normals = {
            'packet_count': rng.randint(1, 50, normal_count),
            'unique_dst_ports': rng.randint(1, 6, normal_count),
            'proto_tcp_ratio': rng.uniform(0.4, 1.0, normal_count),
            'syn_count': rng.randint(0, 3, normal_count),
            'avg_pkt_size': rng.uniform(60, 800, normal_count),
            'total_payload': rng.uniform(0, 4000, normal_count)
        }
        df_norm = pd.DataFrame(normals)

        # Combine: treat honeypot rows as anomalies appended to normals
        df_train = pd.concat([df_norm, self.features_from_df(df_anom)], ignore_index=True)

        # Fit new model
        self.fit(df_train, n_estimators=200, contamination=max(0.001, min(0.05, len(df_anom) / len(df_train))))
        self.save_model()
        return True


# convenience function used by scripts
def train_synthetic_and_save(path=MODEL_PATH):
    rng = np.random.RandomState(42)
    normals = {
        'packet_count': rng.randint(1, 25, 1000),
        'unique_dst_ports': rng.randint(1, 6, 1000),
        'proto_tcp_ratio': rng.uniform(0.4, 1.0, 1000),
        'syn_count': rng.randint(0, 3, 1000),
        'avg_pkt_size': rng.uniform(60, 800, 1000),
        'total_payload': rng.uniform(0, 4000, 1000)
    }
    df_norm = pd.DataFrame(normals)
    det = AnomalyDetector(path)
    det.fit(df_norm)
    det.save_model()
    return det
