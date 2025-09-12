import argparse
import time
from capture.sniffer import read_pcap, capture_live
from features.feature_extractor import aggregate_features
from models.anomaly_detector import AnomalyDetector
from enforcement.rule_manager import RuleManager
from utils.logger import logger, log_event
from utils.alert import send_alert

# === CONFIG ===
THRESHOLD = 0.85        # anomaly score cutoff
MIN_REPEATS = 2         # require this many anomalies before blocking
WINDOW_SECONDS = 2      # time window for live capture
BLOCK_TTL = 3600        # seconds (1 hour)


def process_packets(detector, rule_mgr, packets, mode="pcap"):
    """Process packets in batch or live mode"""
    anomaly_counts = {}

    # Extract features
    features = aggregate_features(packets)
    if features.empty:
        logger.info("No packets in window.")
        return

    # Run predictions
    for _, row in features.iterrows():
        src_ip = row["src_ip"]
        score, is_anomaly = detector.predict(row.drop("src_ip"))

        if score >= THRESHOLD:
            anomaly_counts[src_ip] = anomaly_counts.get(src_ip, 0) + 1

            if anomaly_counts[src_ip] >= MIN_REPEATS:
                logger.warning(f"Anomaly detected from {src_ip} score={score:.3f}")
                rule_id = rule_mgr.block_ip(src_ip, reason=f"{mode}_anomaly", ttl=BLOCK_TTL)
                log_event(src_ip, score, "BLOCKED", rule_id)
                send_alert(src_ip, score)
        else:
            logger.info(f"Normal -> {src_ip} score={score:.3f}")
            log_event(src_ip, score, "NORMAL")


def train_mode():
    """Train model on synthetic dataset"""
    detector = AnomalyDetector()
    detector.train_synthetic()
    detector.save_model()
    logger.info("Training completed and model saved.")


def pcap_mode(pcap_file, dry_run=False):
    """Run IDS on offline pcap file"""
    detector = AnomalyDetector()
    detector.load_model()

    rule_mgr = RuleManager(dry_run=dry_run)
    packets = read_pcap(pcap_file)
    process_packets(detector, rule_mgr, packets, mode="pcap")


def live_mode(iface, run_seconds=20, dry_run=False):
    """Run IDS in live sniffing mode"""
    detector = AnomalyDetector()
    detector.load_model()

    rule_mgr = RuleManager(dry_run=dry_run)

    start = time.time()
    while time.time() - start < run_seconds:
        pkts = capture_live(interface=iface, timeout=WINDOW_SECONDS)
        process_packets(detector, rule_mgr, pkts, mode="live")


def main():
    parser = argparse.ArgumentParser(description="AI Adaptive Firewall (AIAF)")
    parser.add_argument("--mode", choices=["train", "pcap", "live"], required=True)
    parser.add_argument("--pcap", help="Path to pcap file")
    parser.add_argument("--iface", help="Interface for live capture (e.g., wlan0)")
    parser.add_argument("--run-seconds", type=int, default=20, help="Live capture duration")
    parser.add_argument("--dry-run", action="store_true", help="Do not apply iptables rules")
    args = parser.parse_args()

    if args.mode == "train":
        train_mode()
    elif args.mode == "pcap":
        if not args.pcap:
            raise ValueError("--pcap file is required in pcap mode")
        pcap_mode(args.pcap, dry_run=args.dry_run)
    elif args.mode == "live":
        if not args.iface:
            raise ValueError("--iface is required in live mode")
        live_mode(args.iface, run_seconds=args.run_seconds, dry_run=args.dry_run)


if __name__ == "__main__":
    main()

