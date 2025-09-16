# capture/sniffer.py
import utils.scapy_patch
from scapy.all import sniff, rdpcap
from datetime import datetime
import time

def capture_live(interface='wlan0', timeout=10, count=0, prn=None):
    """
    Capture live packets for `timeout` seconds or `count` packets.
    prn: callback(packet)
    """
    # If count>0, sniff will stop after count packets; otherwise it uses timeout
    if count > 0:
        packets = sniff(iface=interface, count=count, prn=prn)
    else:
        packets = sniff(iface=interface, timeout=timeout, prn=prn)
    return packets

def read_pcap(path):
    """Read pcap file and return Scapy packet list"""
    return rdpcap(path)
