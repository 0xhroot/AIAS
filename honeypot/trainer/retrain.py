# trainer/retrain.py
import os
import pandas as pd
from models.anomaly_detector import AnomalyDetector

HONEYPOT_CSV = os.path.join("data", "processed", "honeypot_attacks.csv")
BENIGN_CSV = os.path.join("data", "processed", "benign_samples.csv")  # create or reuse logs/events.csv converted
MODEL_BACKUP = os.path.join("models", "saved_models", "iso_forest_backup.pkl")

def retrain():
    det = AnomalyDetector()
    # load existing benign or create synthetic if missing
    if os.path.exists(BENIGN_CSV):
        df_ben = pd.read_csv(BENIGN_CSV)
    else:
        # create tiny benign sample set (demo)
        df_ben = pd.DataFrame({
            "packet_count":[1,2,3,4,5],
            "unique_dst_ports":[1,1,2,1,1],
            "proto_tcp_ratio":[0.9,0.8,0.95,0.7,0.85],
            "syn_count":[0,0,1,0,0],
            "avg_pkt_size":[120,200,150,220,180],
            "total_payload":[100,300,150,400,200]
        })

    if os.path.exists(HONEYPOT_CSV):
        df_att = pd.read_csv(HONEYPOT_CSV)
        # remove src_ip column if present
        if "src_ip" in df_att.columns:
            df_att = df_att.drop(columns=["src_ip"])
    else:
        print("No honeypot attacks found; aborting retrain.")
        return

    # combine and shuffle
    df_train = pd.concat([df_ben, df_att], ignore_index=True).sample(frac=1.0, random_state=42)

    # backup existing model
    try:
        det.load_model()
        import joblib, shutil
        if os.path.exists(det.model_path):
            # save backup
            shutil.copy(det.model_path, MODEL_BACKUP)
            print("Backed up old model to", MODEL_BACKUP)
    except Exception:
        print("No existing model to backup (ok).")

    # fit and save model
    det.fit(df_train)
    det.save_model()
    print("Retrain complete, model updated.")

if __name__ == "__main__":
    retrain()

