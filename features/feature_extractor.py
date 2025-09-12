# features/feature_extractor.py
import numpy as np
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
from datetime import datetime

def packet_basic_features(pkt):
    """Extract features from one scapy packet (best-effort)"""
    feat = {}
    ts = getattr(pkt, 'time', None)
    feat['timestamp'] = float(ts) if ts else None
    if IP in pkt:
        ip = pkt[IP]
        feat['src_ip'] = ip.src
        feat['dst_ip'] = ip.dst
        feat['ip_len'] = int(ip.len) if hasattr(ip, 'len') else 0
    else:
        feat['src_ip'] = None
        feat['dst_ip'] = None
        feat['ip_len'] = 0
    feat['proto'] = None
    feat['tcp_flags'] = ''
    feat['sport'] = None
    feat['dport'] = None
    if TCP in pkt:
        t = pkt[TCP]
        feat['proto'] = 'TCP'
        feat['tcp_flags'] = str(t.flags)
        feat['sport'] = int(t.sport)
        feat['dport'] = int(t.dport)
        feat['payload_len'] = len(bytes(t.payload)) if t.payload else 0
    elif UDP in pkt:
        u = pkt[UDP]
        feat['proto'] = 'UDP'
        feat['sport'] = int(u.sport)
        feat['dport'] = int(u.dport)
        feat['payload_len'] = len(bytes(u.payload)) if u.payload else 0
    else:
        feat['proto'] = 'OTHER'
        feat['payload_len'] = len(bytes(pkt.payload)) if pkt.payload else 0
    return feat

def aggregate_features(packets, window_seconds=2.0):
    """
    Simple aggregation: group packets in time windows per src_ip and return DataFrame.
    Returns rows with features aggregated per (src_ip, window_start).
    """
    flows = defaultdict(list)
    for pkt in packets:
        pf = packet_basic_features(pkt)
        if not pf['src_ip']:
            continue
        ts = pf['timestamp'] or 0.0
        window = int(ts // window_seconds) * window_seconds
        key = (pf['src_ip'], window)
        flows[key].append(pf)

    rows = []
    for (src_ip, window), lst in flows.items():
        row = {'src_ip': src_ip, 'window_start': window, 'packet_count': len(lst)}
        ports = set()
        protocols = defaultdict(int)
        tcp_syn_count = 0
        total_payload = 0
        sizes = []
        for p in lst:
            ports.add(p['dport'])
            protocols[p['proto']] += 1
            if 'S' in p.get('tcp_flags', ''):
                tcp_syn_count += 1
            total_payload += p.get('payload_len', 0)
            sizes.append(p.get('ip_len', 0) or 0)
        row['unique_dst_ports'] = len(ports)
        row['proto_tcp_ratio'] = protocols.get('TCP',0) / (len(lst) + 1e-6)
        row['syn_count'] = tcp_syn_count
        row['avg_pkt_size'] = float(np.mean(sizes)) if sizes else 0.0
        row['total_payload'] = total_payload
        rows.append(row)
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df = df.fillna(0)
    return df
