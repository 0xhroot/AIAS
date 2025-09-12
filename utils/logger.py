import logging
import os
import csv
import json
from datetime import datetime

LOG_DIR = "logs"
CSV_FILE = os.path.join(LOG_DIR, "events.csv")
JSON_FILE = os.path.join(LOG_DIR, "events.json")

os.makedirs(LOG_DIR, exist_ok=True)

# Normal logger (console + file)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "aiaf.log")),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("AIAF")

def log_event(ip, score, decision, rule_id=None):
    """Log anomaly/normal events to CSV and JSON"""
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "score": score,
        "decision": decision,
        "rule_id": rule_id
    }

    # Append CSV
    write_header = not os.path.exists(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=event.keys())
        if write_header:
            writer.writeheader()
        writer.writerow(event)

    # Append JSON (line by line)
    with open(JSON_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

    logger.info(f"Logged event -> {event}")


def get_logger(name="AIAF"):
    return logging.getLogger(name)

