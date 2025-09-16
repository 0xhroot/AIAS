# honeypot_ingest.py
import os
import json
import glob
import pandas as pd

HONEY_LOG = os.path.join("honeypot", "logs", "honeypot_events.json")
OUT_CSV = os.path.join("data", "processed", "honeypot_attacks.csv")
os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)

def ingest():
    if not os.path.exists(HONEY_LOG):
        print("No honeypot logs yet:", HONEY_LOG)
        return None
    rows = []
    with open(HONEY_LOG, "r") as f:
        for ln in f:
            ln = ln.strip()
            if not ln: continue
            try:
                obj = json.loads(ln)
            except:
                continue
            rows.append(obj)
    if not rows:
        print("No rows parsed")
        return None
    df = pd.DataFrame(rows)
    # simple feature engineering for retrain: convert to numbers expected by AnomalyDetector
    # Map honeypot events to features: these are heuristics for demo; improve in real system.
    df_feat = pd.DataFrame()
    df_feat["src_ip"] = df["src_ip"]
    # number of honeypot events per IP becomes packet_count-like
    agg = df_feat.groupby("src_ip").size().rename("packet_count").reset_index()
    # for other features we use heuristics / constants
    agg["unique_dst_ports"] = 1
    agg["proto_tcp_ratio"] = 1.0
    agg["syn_count"] = 20  # assume multiple SYNs seen for port scans
    agg["avg_pkt_size"] = 300
    agg["total_payload"] = 2000 * agg["packet_count"]

    # save
    agg.to_csv(OUT_CSV, index=False)
    print("Saved honeypot features to", OUT_CSV)
    return OUT_CSV

if __name__ == "__main__":
    ingest()

