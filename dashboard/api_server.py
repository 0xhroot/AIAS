# dashboard/api_server.py
import os
import json
import time
import threading
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS
from pathlib import Path
from enforcement.rule_manager import RuleManager
from utils.logger import logger

# Config
LOG_DIR = Path(__file__).resolve().parents[1] / "logs"  # ../logs
EVENTS_JSON = LOG_DIR / "events.json"
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", 5000))
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_DRY_RUN = os.getenv("DASHBOARD_DRY_RUN", "true").lower() in ("1","true","yes")

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Rule manager (dry-run by default)
rule_mgr = RuleManager(dry_run=DASHBOARD_DRY_RUN)

def read_events(last_n=500):
    """Read last_n events from logs/events.json (line-delimited JSON)."""
    events = []
    if not EVENTS_JSON.exists():
        return events
    with open(EVENTS_JSON, "r") as f:
        # read all lines (file likely small). For large logs implement tail.
        lines = f.readlines()
    # take last_n
    lines = lines[-last_n:]
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            events.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return events

def get_blocked_from_iptables():
    """Best-effort read of iptables rules to show blocked IPs (requires sudo to run iptables-save)."""
    try:
        import subprocess, shlex
        out = subprocess.check_output(shlex.split("iptables -S"), stderr=subprocess.STDOUT).decode()
        blocked = []
        for line in out.splitlines():
            # example line: -A INPUT -s 1.2.3.4/32 -j DROP -m comment --comment "AIAF:live_anomaly"
            if "-j DROP" in line and "AIAF:" in line:
                # try to extract source IP
                parts = line.split()
                if "-s" in parts:
                    idx = parts.index("-s")
                    ip = parts[idx+1]
                else:
                    ip = None
                blocked.append({"rule": line, "ip": ip})
        return blocked
    except Exception as e:
        logger.warning("Could not fetch iptables rules: " + str(e))
        # fallback: return rule_mgr.active_rules (if same process)
        rows = []
        for rid, (cmd, exp) in rule_mgr.active_rules.items():
            rows.append({"rule_id": rid, "cmd": cmd, "expire_at": exp})
        return rows

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/events")
def api_events():
    last_n = int(request.args.get("n", 500))
    events = read_events(last_n=last_n)
    return jsonify({"ok": True, "events": events})

@app.route("/api/blocks")
def api_blocks():
    blocks = get_blocked_from_iptables()
    return jsonify({"ok": True, "blocks": blocks})

@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    """
    Body JSON: { "rule_id": "<rule_id>" } OR { "ip": "1.2.3.4" }
    If rule_id is provided and dashboard is running with same rule_manager instance, use remove_rule.
    If only ip is provided, attempt iptables -D to remove rules matching -s ip -j DROP with AIAF comment.
    """
    data = request.get_json() or {}
    rule_id = data.get("rule_id")
    ip = data.get("ip")

    if not rule_id and not ip:
        return jsonify({"ok": False, "error": "provide rule_id or ip"}), 400

    # If rule_id available and in active_rules, remove
    if rule_id and rule_id in rule_mgr.active_rules:
        rule_mgr.remove_rule(rule_id)
        return jsonify({"ok": True, "removed": rule_id})

    # Else try iptables deletion (best-effort)
    if ip:
        try:
            import subprocess, shlex
            # Find matching rules lines and delete them. This is a simple delete command; be careful!
            # We'll attempt to delete any rule with -s <ip> and AIAF comment
            # Use iptables -D with same options; naive approach: iterate existing rules and delete matching ones.
            out = subprocess.check_output(shlex.split("iptables -S"), stderr=subprocess.STDOUT).decode()
            deleted = []
            for line in out.splitlines():
                if ip in line and "AIAF:" in line:
                    # Convert '-A' line into '-D' line to delete
                    del_line = line.replace("-A", "-D", 1)
                    cmd = "iptables " + del_line
                    subprocess.check_call(cmd, shell=True)
                    deleted.append(del_line)
            return jsonify({"ok": True, "deleted": deleted})
        except Exception as e:
            logger.exception("Failed to delete iptables rule: " + str(e))
            return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": False, "error": "not found"}), 404

# static files served automatically from /static
@app.route("/static/<path:p>")
def static_proxy(p):
    return send_from_directory(app.static_folder, p)

if __name__ == "__main__":
    # If you want the dashboard to reflect rule_mgr.active_rules from a running AIAF process,
    # you must import and share the same RuleManager instance (run dashboard in same process).
    logger.info(f"Starting dashboard on {DASHBOARD_HOST}:{DASHBOARD_PORT} (dry_run={DASHBOARD_DRY_RUN})")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)
