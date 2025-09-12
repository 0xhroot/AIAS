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
