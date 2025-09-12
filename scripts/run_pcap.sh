#!/usr/bin/env bash
# usage: ./run_pcap.sh path/to/file.pcap
PCAP=${1:-data/raw/sample.pcap}
source ../venv/bin/activate
python ../main.py --mode pcap --pcap "$PCAP" --dry-run
