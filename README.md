# AIAF (MVP)

## Quick Start (Arch Linux)
1. create venv:
   python -m venv venv
   source venv/bin/activate

2. install deps:
   pip install -r requirements.txt

3. train baseline model (synthetic demo):
   python main.py --mode train

4. test on pcap (dry-run):
   python main.py --mode pcap --pcap data/raw/sample.pcap --dry-run

5. live dry-run capture (requires root for real capture):
   sudo python main.py --mode live --iface <your_iface> --run-seconds 30 --dry-run

## Notes
- Use `--dry-run` until you are confident; it will not execute iptables.
- Use a lab VM for live tests.

## Working

## AI Model (Isolation Forest)

- We trained a basic anomaly detection model.

- It can score network traffic/events as normal or suspicious/anomalous.

## Event Logging System (utils/logger.py)

Every event (IP, score, decision, rule_id) is saved into:

- logs/events.csv (structured table)

- logs/events.json (line-by-line JSON)

- logs/aiaf.log (normal log file)

## Rule Manager (enforcement)

- Handles blocked IPs list.

- Later can be extended to actually apply firewall rules (iptables/ufw).

## Web Dashboard (Flask + Chart.js)

- Shows live anomaly graph (last 10 minutes) 📈

- Shows blocked IPs 🚫

- Shows recent events 📝

- Auto-refreshes every 4 seconds.

## Traffic Simulator (traffic_simulator.py)

- Generates random fake events (IP + anomaly score).

- Keeps the dashboard alive for demo/testing.

# In short

- Detects anomalies with ML

- Logs them

- Visualizes them in real time on a dashboard

- Can simulate fake attacks for demo
