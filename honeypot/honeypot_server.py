# honeypot/honeypot_server.py
import socket
import threading
import json
import os
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
OUT_FILE = os.path.join(LOG_DIR, "honeypot_events.json")

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 2222  # use same port as HONEYPOT_PORT

def handle_client(conn, addr):
    src_ip, src_port = addr[0], addr[1]
    try:
        conn.settimeout(3.0)
        data = b""
        try:
            data = conn.recv(4096)
        except Exception:
            pass
        # basic response to pretend SSH banner
        try:
            conn.sendall(b"220 honeypot\r\n")
        except Exception:
            pass
        record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": LISTEN_PORT,
            "data_preview": data[:200].decode('latin1', errors='replace')
        }
        with open(OUT_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    finally:
        try:
            conn.close()
        except:
            pass

def run_server(host=LISTEN_HOST, port=LISTEN_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(40)
    print(f"[honeypot] listening on {host}:{port}, logging to {OUT_FILE}")
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("[honeypot] stopped")

if __name__ == "__main__":
    run_server()

