#!/usr/bin/env python3
"""
AIAF main orchestrator (updated)

Adds:
 - saving honeypot samples on REDIRECT
 - immediate retrain with honeypot data
 - re-evaluation of the same sample and immediate BLOCK if post-retrain score >= THRESHOLD_BLOCK
"""
from __future__ import annotations
import argparse
import time
import logging
from typing import Any, Dict

from capture.sniffer import read_pcap, capture_live
from features.feature_extractor import aggregate_features
from models.anomaly_detector import AnomalyDetector
from enforcement.rule_manager import RuleManager
from utils.logger import logger, log_event, save_attack_features
from utils.alert import send_alert

# === CONFIG (tweak) ===
THRESHOLD_BLOCK = 0.85    # score >= -> block
THRESHOLD_REDIRECT = 0.60 # score >= -> redirect to honeypot (but less than block)
MIN_REPEATS = 2           # require this many anomalies in window before action
WINDOW_SECONDS = 2        # capture window for live mode
BLOCK_TTL = 3600          # seconds (1 hour)
HONEYPOT_IP = "127.0.0.1" # honeypot host (for redirect)
HONEYPOT_PORT = 2222      # honeypot listen port (for redirect)
WHITELIST = {"192.168.0.1"}  # safe IPs to never block/redirect

LOG = logging.getLogger("AIAF.main")
LOG.setLevel(logging.INFO)


def get_score_from_detector(detector: Any, feat_input) -> float:
    """
    Best-effort obtain normalized score [0,1] from detector.
    Accepts dict/Series/DataFrame depending on detector implementation.
    """
    try:
        # prefer detector.predict returning a scalar/array
        if hasattr(detector, "predict"):
            out = detector.predict(feat_input)
            # if tuple, pick the numeric element
            if isinstance(out, tuple):
                for v in out:
                    if isinstance(v, (int, float)):
                        return float(max(0.0, min(1.0, v)))
                # fallback
                try:
                    return float(out[0])
                except Exception:
                    pass
            if isinstance(out, (int, float)):
                return float(max(0.0, min(1.0, out)))
            # array-like
            try:
                return float(out[0])
            except Exception:
                pass

        # try predict_score (rows -> array)
        if hasattr(detector, "predict_score"):
            import pandas as pd
            if isinstance(feat_input, dict):
                df = pd.DataFrame([feat_input])
            elif hasattr(feat_input, "to_dict"):
                df = __import__("pandas").DataFrame([feat_input.to_dict()])
            else:
                df = __import__("pandas").DataFrame([feat_input])
            scores = detector.predict_score(df)
            try:
                s = float(scores[0])
                return float(max(0.0, min(1.0, s)))
            except Exception:
                pass

        # try predict_label -> (labels, norm_scores)
        if hasattr(detector, "predict_label"):
            import pandas as pd
            if isinstance(feat_input, dict):
                df = pd.DataFrame([feat_input])
            elif hasattr(feat_input, "to_dict"):
                df = pd.DataFrame([feat_input.to_dict()])
            else:
                df = pd.DataFrame([feat_input])
            labels, norm = detector.predict_label(df)
            try:
                return float(norm[0])
            except Exception:
                pass

    except Exception as e:
        LOG.debug("get_score_from_detector failed: %s", e)

    return 0.0


def process_packets(detector: AnomalyDetector, rule_mgr: RuleManager, packets: list, mode: str = "pcap"):
    """
    Core processing loop for a batch of packets.
    - extract features
    - get score per src_ip
    - if score >= BLOCK threshold and repeated => block
    - if score in [REDIRECT, BLOCK) and repeated => redirect to honeypot, save sample, retrain, re-evaluate and possibly block
    - else log NORMAL
    """
    if not packets:
        LOG.info("[main] No packets in window.")
        return

    feats = aggregate_features(packets)
    if feats is None or getattr(feats, "empty", False):
        LOG.info("[main] No features extracted.")
        return

    anomaly_counts: Dict[str, int] = {}

    for _, row in feats.iterrows():
        src_ip = str(row.get("src_ip", "unknown"))

        # get numeric feature dict for detector (remove src_ip)
        try:
            feat_dict = row.drop(labels=["src_ip"], errors="ignore").to_dict()
        except Exception:
            # fallback: attempt conversion
            feat_dict = dict(row)

        score = get_score_from_detector(detector, feat_dict)

        # update count only when above redirect threshold
        if score >= THRESHOLD_REDIRECT:
            anomaly_counts[src_ip] = anomaly_counts.get(src_ip, 0) + 1
        else:
            anomaly_counts.setdefault(src_ip, anomaly_counts.get(src_ip, 0))

        try:
            # BLOCK
            if score >= THRESHOLD_BLOCK and anomaly_counts.get(src_ip, 0) >= MIN_REPEATS:
                if src_ip in WHITELIST:
                    LOG.info("[main] Whitelisted IP, skipping block: %s", src_ip)
                    log_event(src_ip, score=score, decision="WHITELIST")
                    continue

                LOG.warning("[main] BLOCK -> %s score=%.3f", src_ip, score)
                try:
                    rule_id = rule_mgr.block_ip(src_ip, reason=f"{mode}_auto_block", ttl=BLOCK_TTL)
                except Exception as re:
                    LOG.exception("[main] rule_mgr.block_ip failed: %s", re)
                    rule_id = None
                log_event(src_ip, score=score, decision="BLOCKED", rule_id=rule_id)
                try:
                    send_alert(src_ip, score)
                except Exception:
                    LOG.debug("send_alert failed")
                continue

            # REDIRECT -> honeypot
            if THRESHOLD_REDIRECT <= score < THRESHOLD_BLOCK and anomaly_counts.get(src_ip, 0) >= MIN_REPEATS:
                if src_ip in WHITELIST:
                    LOG.info("[main] Whitelisted IP, skipping redirect: %s", src_ip)
                    log_event(src_ip, score=score, decision="WHITELIST")
                    continue

                LOG.warning("[main] REDIRECT -> %s to honeypot score=%.3f", src_ip, score)
                try:
                    rule_id = rule_mgr.redirect_to_honeypot(
                        src_ip,
                        honeypot_ip=HONEYPOT_IP,
                        honeypot_port=HONEYPOT_PORT,
                        reason=f"{mode}_honeypot_redirect",
                        ttl=BLOCK_TTL
                    )
                except Exception as re:
                    LOG.exception("[main] rule_mgr.redirect_to_honeypot failed: %s", re)
                    rule_id = None

                # Log redirect
                log_event(src_ip, score=score, decision="REDIRECTED_TO_HONEYPOT", rule_id=rule_id)

                # Save features for retraining (so future identical attacks get blocked)
                try:
                    save_attack_features(src_ip, feat_dict)
                except Exception as e:
                    LOG.exception("[main] save_attack_features failed: %s", e)

                # Immediately retrain (if detector supports it)
                retrained = False
                try:
                    if hasattr(detector, "retrain_with_honeypot"):
                        retrained = detector.retrain_with_honeypot()
                    elif hasattr(detector, "retrain"):
                        retrained = detector.retrain()
                    else:
                        retrained = False
                    LOG.info("[main] retrain_with_honeypot returned: %s", retrained)
                except Exception as e:
                    LOG.exception("[main] retrain failed: %s", e)
                    retrained = False

                # After retraining, re-evaluate the same feature vector and block immediately if now malicious
                if retrained:
                    try:
                        new_score = get_score_from_detector(detector, feat_dict)
                        LOG.info("[main] post-retrain score for %s = %.3f", src_ip, new_score)
                        if new_score >= THRESHOLD_BLOCK:
                            LOG.warning("[main] post-retrain immediate BLOCK %s score=%.3f", src_ip, new_score)
                            try:
                                rule_id2 = rule_mgr.block_ip(src_ip, reason=f"{mode}_postretrain_block", ttl=BLOCK_TTL)
                            except Exception as e:
                                LOG.exception("[main] post-retrain block failed: %s", e)
                                rule_id2 = None
                            log_event(src_ip, score=new_score, decision="BLOCKED", rule_id=rule_id2)
                            try:
                                send_alert(src_ip, new_score)
                            except Exception:
                                LOG.debug("send_alert failed")
                            continue
                    except Exception as e:
                        LOG.exception("[main] post-retrain re-eval failed: %s", e)

                continue

            # NORMAL
            LOG.info("[main] NORMAL -> %s score=%.3f", src_ip, score)
            log_event(src_ip, score=score, decision="NORMAL")

        except Exception as e:
            LOG.exception("[main] exception processing %s: %s", src_ip, e)
            log_event(src_ip, score=score, decision="ERROR")


def train_mode():
    """
    Train a demo/synthetic model using AnomalyDetector's training utility.
    """
    LOG.info("[main] Starting training...")
    detector = AnomalyDetector()
    # Try common training entrypoints if available
    try:
        if hasattr(detector, "train_synthetic"):
            detector.train_synthetic()
        elif hasattr(detector, "train_synthetic_and_save"):
            detector.train_synthetic_and_save()
        elif hasattr(detector, "fit"):
            # fallback synthetic dataset
            import numpy as np
            import pandas as pd
            rng = np.random.RandomState(42)
            df = pd.DataFrame({
                "packet_count": rng.randint(1, 50, 500),
                "unique_dst_ports": rng.randint(1, 10, 500),
                "proto_tcp_ratio": rng.uniform(0.3, 1.0, 500),
                "syn_count": rng.randint(0, 5, 500),
                "avg_pkt_size": rng.uniform(60, 1000, 500),
                "total_payload": rng.uniform(0, 5000, 500)
            })
            detector.fit(df)
    except Exception as e:
        LOG.exception("[main] training failed: %s", e)

    # save if possible
    try:
        if hasattr(detector, "save_model"):
            detector.save_model()
    except Exception:
        LOG.debug("detector.save_model failed (ignored)")

    LOG.info("[main] Training finished.")


def pcap_mode(pcap_file: str, dry_run: bool = False):
    LOG.info("[main] Running in PCAP mode on %s", pcap_file)
    detector = AnomalyDetector()
    try:
        if hasattr(detector, "load_model"):
            detector.load_model()
        elif hasattr(detector, "load"):
            detector.load()
    except Exception as e:
        LOG.warning("[main] Could not load model: %s", e)

    rule_mgr = RuleManager(dry_run=dry_run, whitelist=WHITELIST)
    packets = read_pcap(pcap_file)
    process_packets(detector, rule_mgr, packets, mode="pcap")


def live_mode(iface: str, run_seconds: int = 20, dry_run: bool = False):
    LOG.info("[main] Starting live mode on iface=%s for %ds (dry_run=%s)", iface, run_seconds, dry_run)
    detector = AnomalyDetector()
    try:
        if hasattr(detector, "load_model"):
            detector.load_model()
        elif hasattr(detector, "load"):
            detector.load()
    except Exception as e:
        LOG.warning("[main] Could not load model: %s", e)

    rule_mgr = RuleManager(dry_run=dry_run, whitelist=WHITELIST)

    start = time.time()
    while time.time() - start < run_seconds:
        try:
            pkts = capture_live(interface=iface, timeout=WINDOW_SECONDS)
            process_packets(detector, rule_mgr, pkts, mode="live")
        except KeyboardInterrupt:
            LOG.info("[main] KeyboardInterrupt, exiting live loop")
            break
        except Exception as e:
            LOG.exception("[main] Exception in live capture loop: %s", e)
            time.sleep(1)


def parse_args():
    p = argparse.ArgumentParser(description="AIAF - Adaptive firewall with honeypot redirect")
    p.add_argument("--mode", choices=["train", "pcap", "live"], required=True)
    p.add_argument("--pcap", help="Path to pcap file (for pcap mode)")
    p.add_argument("--iface", help="Interface for live mode (e.g., wlan0)")
    p.add_argument("--run-seconds", type=int, default=20, help="Duration for live mode")
    p.add_argument("--dry-run", action="store_true", help="Do not apply iptables rules (RuleManager dry-run)")
    return p.parse_args()


def main():
    args = parse_args()
    if args.mode == "train":
        train_mode()
    elif args.mode == "pcap":
        if not args.pcap:
            raise ValueError("--pcap is required for pcap mode")
        pcap_mode(args.pcap, dry_run=args.dry_run)
    elif args.mode == "live":
        if not args.iface:
            raise ValueError("--iface is required for live mode")
        live_mode(args.iface, run_seconds=args.run_seconds, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
