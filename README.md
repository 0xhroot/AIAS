<div align="center">

```
 █████╗ ██╗ █████╗ ███████╗
██╔══██╗██║██╔══██╗██╔════╝
███████║██║███████║███████╗
██╔══██║██║██╔══██║╚════██║
██║  ██║██║██║  ██║███████║
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

AI Adaptive Security  —  ML-Powered Network Firewall
```

**A self-learning firewall that doesn't just block — it understands.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Dashboard-Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-MIT-00FF88?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://linux.org)
[![Stars](https://img.shields.io/github/stars/0xhroot/AIAS?style=for-the-badge&color=FFD700)](https://github.com/0xhroot/AIAS/stargazers)

<br/>

> *"Traditional firewalls follow rules. AIAS writes its own."*

<br/>

[**How It Works**](#-how-it-works) · [**Architecture**](#-system-architecture) · [**Installation**](#-installation) · [**Dashboard**](#-web-dashboard) · [**Roadmap**](#-roadmap)

</div>

---

## ⚡ What is AIAS?

**AIAS (AI Adaptive Security)** is a machine learning-powered network firewall that goes beyond static rules and signatures. While tools like pfSense, iptables, Snort, and Suricata rely on predefined rule sets, AIAS **learns traffic behavior over time** and autonomously adapts its filtering logic.

It is not just an IDS (Intrusion Detection System) that raises alerts. AIAS is an **active AI filter** — it detects, scores, logs, and enforces decisions on network traffic in real time, visualizing everything through a live web dashboard.

| Traditional Firewall | AIAS |
|---|---|
| Blocks by rules/signatures | Learns normal behavior, flags deviations |
| Needs manual rule updates | Auto-adapts over time |
| Binary allow/block | Anomaly scoring with confidence levels |
| Detect only (IDS) | Active enforcement |
| Blind to novel attacks | Catches zero-day patterns via ML |

---

## 🧠 How It Works

AIAS operates in a continuous pipeline across three phases:

### 1. Capture
Raw network packets are captured from a live interface or loaded from a `.pcap` file. Each packet is parsed and normalized into feature vectors representing connection characteristics.

### 2. Detect
An **Isolation Forest** model — a proven unsupervised anomaly detection algorithm — scores each traffic event. It learns what "normal" looks like and assigns outlier scores to anything that deviates. No labeled attack data is required.

### 3. Enforce
Events that exceed the anomaly threshold are flagged. Their IPs are added to the blocked list managed by the **Rule Manager**, which can hook into `iptables`/`ufw` for real firewall enforcement. Every decision is logged across three formats simultaneously.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AIAS PIPELINE                          │
│                                                                 │
│  ┌─────────────┐     ┌──────────────┐     ┌─────────────────┐  │
│  │   CAPTURE   │────►│   FEATURES   │────►│   DETECTION     │  │
│  │             │     │              │     │                 │  │
│  │ capture/    │     │ features/    │     │ detection/      │  │
│  │ ─ pcap load │     │ ─ extract    │     │ ─ IsolationForest│  │
│  │ ─ live iface│     │ ─ normalize  │     │ ─ anomaly score │  │
│  │ ─ simulator │     │ ─ vectorize  │     │ ─ threshold     │  │
│  └─────────────┘     └──────────────┘     └────────┬────────┘  │
│                                                    │           │
│              ┌─────────────────────────────────────┘           │
│              ▼                                                  │
│  ┌─────────────────┐     ┌──────────────┐                      │
│  │   ENFORCEMENT   │     │    LOGGING   │                      │
│  │                 │     │              │                      │
│  │ enforcement/    │     │ utils/       │                      │
│  │ ─ rule manager  │     │ ─ events.csv │                      │
│  │ ─ blocked IPs   │     │ ─ events.json│                      │
│  │ ─ iptables hook │     │ ─ aiaf.log   │                      │
│  └────────┬────────┘     └──────┬───────┘                      │
│           │                    │                               │
│           └──────────┬─────────┘                               │
│                      ▼                                         │
│          ┌───────────────────────┐                             │
│          │    WEB DASHBOARD      │                             │
│          │                       │                             │
│          │ dashboard/            │                             │
│          │ ─ Flask server        │                             │
│          │ ─ Chart.js live graph │                             │
│          │ ─ Blocked IPs table   │                             │
│          │ ─ Event stream        │                             │
│          │ ─ Auto-refresh (4s)   │                             │
│          └───────────────────────┘                             │
└─────────────────────────────────────────────────────────────────┘

            ┌──────────────────────────────┐
            │       MODELS LAYER           │
            │  models/                     │
            │  ─ trained IsolationForest   │
            │  ─ feature scaler            │
            │  ─ model persistence (.pkl)  │
            └──────────────────────────────┘

            ┌──────────────────────────────┐
            │       HONEYPOT (Optional)    │
            │  honeypot/                   │
            │  ─ decoy service listener    │
            │  ─ trap malicious probes     │
            └──────────────────────────────┘
```

---

## 📁 Project Structure

```
AIAS/
│
├── main.py                    # Entry point — train / pcap / live modes
├── traffic_simulator.py       # Fake event generator for demo/testing
├── requirements.txt           # Python dependencies
│
├── capture/                   # Packet capture subsystem
│   └── ...                    # pcap parsing, live interface capture
│
├── features/                  # Feature engineering
│   └── ...                    # Packet → ML feature vector pipeline
│
├── detection/                 # ML anomaly detection
│   └── ...                    # Isolation Forest model wrapper
│
├── enforcement/               # Rule enforcement engine
│   └── ...                    # Blocked IP management, iptables bridge
│
├── models/                    # Persisted ML model artifacts
│   └── ...                    # .pkl model files, scalers
│
├── dashboard/                 # Flask web dashboard
│   └── ...                    # Routes, templates, Chart.js frontend
│
├── honeypot/                  # Decoy service (optional trap layer)
│   └── ...
│
├── utils/                     # Shared utilities
│   └── logger.py              # Triple-format event logger
│
├── data/
│   └── raw/
│       └── sample.pcap        # Sample capture file for testing
│
├── logs/                      # Runtime output (auto-generated)
│   ├── events.csv             # Structured event table
│   ├── events.json            # Line-by-line JSON log
│   └── aiaf.log               # Human-readable log file
│
└── scripts/                   # Helper/setup scripts
```

---

## 🤖 AI Model — Isolation Forest

AIAS uses **Isolation Forest**, an unsupervised anomaly detection algorithm from scikit-learn, as its core detection engine.

### Why Isolation Forest?

- **No labeled data required** — learns from normal traffic patterns alone
- **Efficient at high dimensions** — network traffic has many features
- **Fast inference** — scores events in microseconds at runtime
- **Effective at isolating rare events** — anomalies are easier to isolate by random partitioning

### How it scores traffic

```
Normal Traffic     → Score close to 0     → ALLOW
Suspicious Traffic → Score approaching -1 → FLAG / BLOCK

Threshold: configurable contamination factor (default ~5% outliers)
```

### Training Modes

```bash
# Train on synthetic baseline data
python main.py --mode train

# Score events from a pcap file (dry run, no enforcement)
python main.py --mode pcap --pcap data/raw/sample.pcap --dry-run

# Live capture from a network interface
sudo python main.py --mode live --iface eth0 --run-seconds 60 --dry-run
```

---

## 📊 Event Logging

Every traffic decision is written to **three formats simultaneously** via `utils/logger.py`:

| File | Format | Purpose |
|---|---|---|
| `logs/events.csv` | Structured CSV | Data analysis, spreadsheet import |
| `logs/events.json` | Line-by-line JSON | Log aggregators (ELK, Splunk, etc.) |
| `logs/aiaf.log` | Human-readable | Terminal monitoring, tail -f |

### Log Schema

```
┌────────────┬──────────────┬───────────┬──────────┬───────────────────┐
│ timestamp  │  source_ip   │   score   │ decision │     rule_id       │
├────────────┼──────────────┼───────────┼──────────┼───────────────────┤
│ 1726172400 │ 192.168.1.45 │ -0.823    │ BLOCK    │ anomaly_threshold │
│ 1726172401 │ 10.0.0.12    │  0.021    │ ALLOW    │ normal_traffic    │
│ 1726172402 │ 172.16.5.99  │ -0.991    │ BLOCK    │ anomaly_threshold │
└────────────┴──────────────┴───────────┴──────────┴───────────────────┘
```

---

## 🌐 Web Dashboard

The Flask-powered dashboard provides a real-time view of everything AIAS detects.

**Features:**
- 📈 **Live anomaly score graph** — rolling 10-minute window via Chart.js
- 🚫 **Blocked IPs table** — all enforcement decisions in one place
- 📝 **Recent events stream** — last N events with score and decision
- 🔄 **Auto-refresh every 4 seconds** — no manual reload needed

**Starting the dashboard:**

```bash
# Dashboard starts automatically with main.py
# Or run standalone:
python dashboard/app.py
```

Then open: `http://localhost:5000`

---

## 🎯 Traffic Simulator

`traffic_simulator.py` generates randomized fake traffic events for demo and testing purposes — no real network interface or pcap required.

```bash
python traffic_simulator.py
```

This keeps the dashboard alive and populated during demos, simulating a mix of normal and anomalous events with randomized IPs and scores.

---

## 🛠️ Installation

### Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.10+ | Tested on 3.10, 3.11 |
| Arch Linux / Debian / Ubuntu | Any modern Linux |
| Root access | Required for live capture only |
| pip | Package manager |

### Step 1 — Clone

```bash
git clone https://github.com/0xhroot/AIAS.git
cd AIAS
```

### Step 2 — Virtual Environment

```bash
python -m venv venv
source venv/bin/activate
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Train the Model

```bash
python main.py --mode train
```

This trains the Isolation Forest on synthetic baseline data and saves the model to `models/`.

---

## ▶️ Running AIAS

### Mode 1 — PCAP Analysis (Safest, no root needed)

```bash
python main.py --mode pcap --pcap data/raw/sample.pcap --dry-run
```

### Mode 2 — Live Capture Dry Run (Root required, no enforcement)

```bash
sudo python main.py --mode live --iface eth0 --run-seconds 30 --dry-run
```

### Mode 3 — Live Capture with Enforcement (Root required)

```bash
# ⚠️ This will apply real iptables rules. Use only in a lab VM.
sudo python main.py --mode live --iface eth0 --run-seconds 60
```

### Mode 4 — Demo with Simulator

```bash
# Terminal 1: Run simulator
python traffic_simulator.py

# Terminal 2: Watch dashboard
python dashboard/app.py
# Open http://localhost:5000
```

<img width="1645" height="814" alt="Shot-2025-09-12-220206" src="https://github.com/user-attachments/assets/759b4585-67cf-40a3-9ece-f0c673b0db97" />

<img width="1920" height="1080" alt="Shot-2025-09-12-225111" src="https://github.com/user-attachments/assets/9c4b74c8-f887-4573-84e6-c9e072de8f43" />

<img width="1817" height="964" alt="Shot-2025-09-12-225340" src="https://github.com/user-attachments/assets/59bf2ced-1e43-4a32-8f87-8e247d68a80e" />

<img width="1824" height="958" alt="Shot-2025-09-12-225323" src="https://github.com/user-attachments/assets/ed5ca177-5c0d-4a5e-aef6-d027847688f4" />

<img width="1833" height="883" alt="Shot-2025-09-12-225210" src="https://github.com/user-attachments/assets/7c6820f5-30a9-4ef6-964f-084c6736c777" />

[![GitHub](https://img.shields.io/badge/GitHub-0xhroot-181717?style=for-the-badge&logo=github)](https://github.com/0xhroot)


> ⚠️ **Always use `--dry-run` until you are confident in your environment. Test live enforcement only in an isolated lab VM.**

---

## ⚙️ Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.10+ | Core runtime |
| ML Engine | scikit-learn (Isolation Forest) | Anomaly detection |
| Packet Capture | Scapy / pcap | Network traffic ingestion |
| Feature Engineering | NumPy, Pandas | Packet → vector pipeline |
| Web Dashboard | Flask | Backend API + HTML serving |
| Frontend Charts | Chart.js | Live anomaly visualization |
| Logging | Custom logger | CSV + JSON + plaintext |
| Enforcement | iptables / ufw bridge | Active blocking |
| Persistence | Pickle (.pkl) | Model save/load |
| Shell | Bash scripts | Setup automation |

---

## 🔐 Security Considerations

- **Dry-run by default** — `--dry-run` flag prevents any real iptables modification
- **Honeypot layer** — optional decoy services in `honeypot/` to trap active probers
- **No network egress** — AIAS does not phone home or send data externally
- **Lab VM recommended** — always test live enforcement in an isolated environment before production use
- **Root only when necessary** — only live capture mode requires elevated privileges

---

## 🆚 AIAS vs Traditional Tools

| Feature | Snort/Suricata | pfSense | iptables | **AIAS** |
|---|---|---|---|---|
| Signature-based | ✅ | ✅ | ✅ | ❌ not needed |
| ML anomaly detection | ❌ | ❌ | ❌ | ✅ |
| Zero-day potential | ❌ | ❌ | ❌ | ✅ |
| Auto-adapting rules | ❌ | ❌ | ❌ | ✅ |
| Live dashboard | ⚠️ partial | ✅ | ❌ | ✅ |
| No rule DB required | ❌ | ❌ | ❌ | ✅ |
| Lightweight Python | ❌ | ❌ | ✅ | ✅ |

---

## 🗺️ Roadmap

- [ ] **Deep Packet Inspection** — Payload-level feature extraction for richer ML input
- [ ] **Multi-model ensemble** — Combine Isolation Forest + One-Class SVM + Autoencoder
- [ ] **Online learning** — Continuously retrain model on incoming traffic without restart
- [ ] **Alert webhooks** — POST to Slack, Discord, or PagerDuty on high-severity events
- [ ] **GeoIP tagging** — Annotate events with country/ASN data
- [ ] **Docker container** — One-command deploy with all dependencies bundled
- [ ] **Prometheus metrics** — Export anomaly scores as time-series for Grafana
- [ ] **IPv6 support** — Extend capture and enforcement to IPv6 traffic
- [ ] **CLI TUI** — Terminal dashboard using Rich or Textual as dashboard alternative
- [ ] **pcap export** — Save flagged sessions as pcap for forensic review

---

## 🚀 Releases

### v1.0.0 — AIAF Complete Release
> 📅 October 2025

First public release. Includes full ML pipeline, live dashboard, traffic simulator, and enforcement layer.

[⬇️ Download ZIP](../../releases/tag/ZIP)

---

## ⚠️ Disclaimer

AIAS is a **research and educational project**. It is intended for use in isolated lab environments. The author takes no responsibility for misuse, unintended blocking, or network disruption caused by running this tool in production environments. Always test with `--dry-run` first.

---

## 📄 License

```
MIT License — Copyright (c) 2025 0xhroot

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies, subject to the MIT license conditions.
```

---

<div align="center">

**Built by [0xhroot](https://github.com/0xhroot)**

*Rules are for firewalls. Learning is for AIAS.*


</div>


<img width="1833" height="883" alt="Shot-2025-09-12-225210" src="https://github.com/user-attachments/assets/30c821a2-e997-40b0-9283-f32a0b68a6c6" />
