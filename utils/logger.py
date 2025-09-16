# utils/logger.py
import logging
import os
import csv
import json
from datetime import datetime, timezone

LOG_DIR = "logs"
CSV_FILE = os.path.join(LOG_DIR, "events.csv")
JSON_FILE = os.path.join(LOG_DIR, "events.json")

HONEYPOT_DATA = os.path.join("data", "processed", "honeypot_attacks.csv")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(os.path.dirname(HONEYPOT_DATA), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "aiaf.log")),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("AIAF")

def iso_now():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()

def log_event(ip, score=None, decision="NORMAL", rule_id=None, extra=None):
    """
    Write NDJSON and append CSV.
    Keys: timestamp (ISO), ip, score, decision, rule_id
    """
    event = {
        "timestamp": iso_now(),
        "ip": ip,
        "score": float(score) if score is not None else None,
        "decision": decision,
        "rule_id": rule_id
    }
    if extra and isinstance(extra, dict):
        for k,v in extra.items():
            if k not in event:
                event[k] = v

    # NDJSON line (flush + fsync to ensure dashboard reads immediately)
    with open(JSON_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass

    # CSV
    write_header = not os.path.exists(CSV_FILE)
    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=event.keys())
        if write_header:
            writer.writeheader()
        writer.writerow(event)

    logger.info(f"Logged event -> {event}")

def save_attack_features(src_ip, features: dict):
    """
    Save attack features (one row) to data/processed/honeypot_attacks.csv for retraining.
    Feature dict must contain the same feature names the detector expects.
    """
    import pandas as pd
    df = pd.DataFrame([features])
    header = not os.path.exists(HONEYPOT_DATA)
    df.to_csv(HONEYPOT_DATA, mode="a", index=False, header=header)
    logger.info("Saved honeypot sample for %s -> %s", src_ip, HONEYPOT_DATA)
