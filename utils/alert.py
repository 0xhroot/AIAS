import requests
import os

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")  # set in env
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_alert(ip, score):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    msg = f"🚨 AIAF ALERT 🚨\nSuspicious IP: {ip}\nAnomaly Score: {score:.3f}"
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": msg})

