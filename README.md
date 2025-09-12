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

6. live dry-run capture (requires root for real capture):
   sudo python main.py --mode live --iface <your_iface> --run-seconds 30 --dry-run


    <img width="1645" height="814" alt="Shot-2025-09-12-220206" src="https://github.com/user-attachments/assets/759b4585-67cf-40a3-9ece-f0c673b0db97" />


## Notes
- Use `--dry-run` until you are confident; it will not execute iptables.
- Use a lab VM for live tests.


## Demo


<img width="1920" height="1080" alt="Shot-2025-09-12-225111" src="https://github.com/user-attachments/assets/9c4b74c8-f887-4573-84e6-c9e072de8f43" />


<img width="1817" height="964" alt="Shot-2025-09-12-225340" src="https://github.com/user-attachments/assets/59bf2ced-1e43-4a32-8f87-8e247d68a80e" />


<img width="1824" height="958" alt="Shot-2025-09-12-225323" src="https://github.com/user-attachments/assets/ed5ca177-5c0d-4a5e-aef6-d027847688f4" />


<img width="1833" height="883" alt="Shot-2025-09-12-225210" src="https://github.com/user-attachments/assets/7c6820f5-30a9-4ef6-964f-084c6736c777" />


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
<img width="1833" height="883" alt="Shot-2025-09-12-225210" src="https://github.com/user-attachments/assets/30c821a2-e997-40b0-9283-f32a0b68a6c6" />


## Traffic Simulator (traffic_simulator.py)

- Generates random fake events (IP + anomaly score).

- Keeps the dashboard alive for demo/testing.

# In short

- Detects anomalies with ML

- Logs them

- Visualizes them in real time on a dashboard

- Can simulate fake attacks for demo

