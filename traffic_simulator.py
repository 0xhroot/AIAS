import random
import time
from utils.logger import log_event

# Some fake IP pool for simulation
FAKE_IPS = [
    "192.168.0.10", "192.168.0.22", "10.0.0.5",
    "172.16.0.8", "203.0.113.15", "8.8.8.8"
]

# Decisions for events
DECISIONS = ["NORMAL", "BLOCKED", "SUSPICIOUS"]

def simulate_traffic(interval=3):
    """
    Generate random events every 'interval' seconds.
    """
    print(f"[SIM] Starting traffic simulator (interval={interval}s)...")
    try:
        while True:
            ip = random.choice(FAKE_IPS)
            score = round(random.uniform(0.0, 1.0), 2)

            # Random decision logic
            if score > 0.8:
                decision = "BLOCKED"
                rule_id = "iso_forest"
            elif score > 0.5:
                decision = "SUSPICIOUS"
                rule_id = "heuristic"
            else:
                decision = "NORMAL"
                rule_id = None

            # Log event using your logger
            log_event(ip, score, decision, rule_id)

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[SIM] Simulator stopped by user.")

if __name__ == "__main__":
    simulate_traffic(interval=4)  # change to 2 or 5 if you want faster/slower
