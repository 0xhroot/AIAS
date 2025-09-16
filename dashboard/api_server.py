# dashboard/api_server.py
import os
import json
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS

# Optional psutil for process inspection
# dashboard/api_server.py
import os
import json
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS

try:
    import psutil
except Exception:
    psutil = None

from enforcement.rule_manager import RuleManager
from utils.logger import logger

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
EVENTS_JSON = LOG_DIR / "events.json"        # main AIAF events (NDJSON)
HONEYPOT_LOG = ROOT / "honeypot" / "logs" / "honeypot_events.json"
HONEYPOT_STDOUT = LOG_DIR / "honeypot_stdout.log"
HONEYPOT_STDERR = LOG_DIR / "honeypot_stderr.log"
RETRAIN_LOG = LOG_DIR / "retrain.log"
RETRAIN_HISTORY = LOG_DIR / "retrain_history.jsonl"  # line-delimited records
MONITOR_STDOUT = LOG_DIR / "monitor_stdout.log"
MONITOR_STDERR = LOG_DIR / "monitor_stderr.log"

DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", 5000))
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_DRY_RUN = os.getenv("DASHBOARD_DRY_RUN", "true").lower() in ("1", "true", "yes")

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

rule_mgr = RuleManager(dry_run=DASHBOARD_DRY_RUN)

# Honeypot subprocess management
honeypot_lock = threading.Lock()
honeypot_proc = None

# Retrain subprocess management
retrain_lock = threading.Lock()
retrain_proc = None
auto_retrain_enabled = False
# last processed mtime of honeypot log used by watcher
_last_honeypot_mtime = 0


# ------------ Utilities -------------
def safe_read_lines(p: Path, n=500):
    if not p.exists():
        return []
    with open(p, "r", errors="ignore") as f:
        lines = f.readlines()
    return lines[-n:]


def _iso_from_epoch(val):
    try:
        # val may be float/int seconds
        t = float(val)
        return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()
    except Exception:
        return None


def normalize_event(raw: dict) -> dict:
    """
    Normalize different event JSON shapes into:
      { "timestamp": ISO8601 str, "ip": str, "score": float or None, "decision": str, ... }
    Accepts variations produced by different parts of AIAF ('timestamp', 'ts', 'time', 'label', 'decision', 'ip', 'src_ip').
    """
    ev = {}
    # timestamp
    if "timestamp" in raw:
        ts = raw.get("timestamp")
        # if already ISO-like, keep
        try:
            # if numeric string or number
            if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.replace('.', '', 1).isdigit()):
                ev["timestamp"] = _iso_from_epoch(ts) or str(ts)
            else:
                # attempt to parse then reformat
                ev["timestamp"] = str(datetime.fromisoformat(ts)) if "T" in str(ts) else str(ts)
        except Exception:
            ev["timestamp"] = str(ts)
    elif "ts" in raw or "time" in raw:
        val = raw.get("ts", raw.get("time"))
        iso = _iso_from_epoch(val)
        ev["timestamp"] = iso or str(val)
    else:
        # fallback to now
        ev["timestamp"] = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()

    # ip
    ev["ip"] = raw.get("ip") or raw.get("src_ip") or raw.get("source") or raw.get("src") or raw.get("address") or None

    # score
    sc = raw.get("score")
    if sc is None:
        # maybe 'anomaly_score' or 's' or 'value'
        sc = raw.get("anomaly_score") or raw.get("s") or raw.get("value")
    try:
        ev["score"] = float(sc) if sc is not None else None
    except Exception:
        ev["score"] = None

    # decision/label
    dec = raw.get("decision") or raw.get("label") or raw.get("action") or raw.get("result")
    if dec:
        ev["decision"] = str(dec).upper()
    else:
        # heuristic: if score high -> SUSPICIOUS else NORMAL
        if ev["score"] is not None:
            ev["decision"] = "SUSPICIOUS" if ev["score"] >= 0.6 else "NORMAL"
        else:
            ev["decision"] = raw.get("status", raw.get("state", "NORMAL")).upper()

    # preserve raw other fields for frontend if needed
    for k, v in raw.items():
        if k in ("timestamp", "ts", "time", "ip", "src_ip", "score", "decision", "label", "action"):
            continue
        ev[k] = v

    return ev


def read_ndjson(path: Path, last_n=500):
    events = []
    if not path.exists():
        return events
    lines = safe_read_lines(path, last_n)
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            raw = json.loads(ln)
        except Exception:
            continue
        try:
            events.append(normalize_event(raw))
        except Exception:
            # fallback raw shape minimally mapped
            events.append({"timestamp": datetime.utcnow().isoformat(), "ip": raw.get("ip") or raw.get("src_ip"), "score": raw.get("score"), "decision": raw.get("decision") or raw.get("label", "NORMAL")})
    return events


def append_retrain_history(entry: dict):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(RETRAIN_HISTORY, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ------------ Honeypot control endpoints -------------
@app.route("/api/honeypot/status")
def api_honeypot_status():
    """Return internal start/stop state and last log time."""
    with honeypot_lock:
        running = (honeypot_proc is not None and honeypot_proc.poll() is None)
        pid = honeypot_proc.pid if (honeypot_proc and honeypot_proc.poll() is None) else None
    mtime = None
    if HONEYPOT_LOG.exists():
        mtime = HONEYPOT_LOG.stat().st_mtime
    return jsonify({"ok": True, "running": running, "pid": pid, "honeypot_mtime": mtime})


@app.route("/api/honeypot/start", methods=["POST"])
def api_honeypot_start():
    """Start honeypot_server.py as subprocess (same venv/python)."""
    global honeypot_proc
    with honeypot_lock:
        if honeypot_proc and honeypot_proc.poll() is None:
            return jsonify({"ok": False, "error": "honeypot already running", "pid": honeypot_proc.pid}), 400

        os.makedirs(HONEYPOT_LOG.parent, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)

        cmd = [sys.executable, str(ROOT / "honeypot" / "honeypot_server.py")]
        stdout_f = open(HONEYPOT_STDOUT, "a")
        stderr_f = open(HONEYPOT_STDERR, "a")
        try:
            honeypot_proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=stdout_f, stderr=stderr_f, env=os.environ)
        except Exception as e:
            logger.exception("Failed to start honeypot: %s", e)
            return jsonify({"ok": False, "error": str(e)}), 500
        logger.info("Started honeypot pid=%s", honeypot_proc.pid)
        return jsonify({"ok": True, "started": True, "pid": honeypot_proc.pid})


@app.route("/api/honeypot/stop", methods=["POST"])
def api_honeypot_stop():
    global honeypot_proc
    with honeypot_lock:
        if not honeypot_proc or honeypot_proc.poll() is not None:
            return jsonify({"ok": False, "error": "honeypot not running"}), 400
        try:
            honeypot_proc.terminate()
            try:
                honeypot_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                honeypot_proc.kill()
            pid = honeypot_proc.pid
            honeypot_proc = None
            logger.info("Stopped honeypot pid=%s", pid)
            return jsonify({"ok": True, "stopped": True, "pid": pid})
        except Exception as e:
            logger.exception("Failed to stop honeypot: %s", e)
            return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/honeypot/events")
def api_honeypot_events():
    """Return last N honeypot events (NDJSON)."""
    n = int(request.args.get("n", 200))
    ev = read_ndjson(HONEYPOT_LOG, last_n=n)
    return jsonify({"ok": True, "events": ev})


# ------------ Retrain control endpoints -------------
@app.route("/api/honeypot/retrain", methods=["POST"])
def api_honeypot_retrain():
    """Trigger retrain now. Runs trainer as subprocess and streams log to RETRAIN_LOG."""
    global retrain_proc
    with retrain_lock:
        if retrain_proc and retrain_proc.poll() is None:
            return jsonify({"ok": False, "error": "retrain already running", "pid": retrain_proc.pid}), 400

        os.makedirs(LOG_DIR, exist_ok=True)
        # run `python -m honeypot.trainer.retrain` to ensure imports work
        cmd = [sys.executable, "-m", "honeypot.trainer.retrain"]
        stdout_f = open(RETRAIN_LOG, "a")
        stderr_f = open(RETRAIN_LOG, "a")
        try:
            retrain_proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=stdout_f, stderr=stderr_f, env=os.environ)
        except Exception as e:
            logger.exception("Failed to start retrain: %s", e)
            return jsonify({"ok": False, "error": str(e)}), 500

        # record history entry
        entry = {"ts": time.time(), "action": "manual_retrain", "pid": retrain_proc.pid}
        append_retrain_history(entry)
        logger.info("Started retrain pid=%s", retrain_proc.pid)
        return jsonify({"ok": True, "started": True, "pid": retrain_proc.pid})


@app.route("/api/honeypot/retrain_status")
def api_retrain_status():
    with retrain_lock:
        running = retrain_proc is not None and retrain_proc.poll() is None
        pid = retrain_proc.pid if (retrain_proc and retrain_proc.poll() is None) else None
    # return last 200 lines of retrain.log
    lines = safe_read_lines(RETRAIN_LOG, 400) if Path(RETRAIN_LOG).exists() else []
    return jsonify({"ok": True, "running": running, "pid": pid, "log": "".join(lines)})


@app.route("/api/honeypot/retrain_history")
def api_retrain_history():
    entries = []
    if Path(RETRAIN_HISTORY).exists():
        with open(RETRAIN_HISTORY, "r") as f:
            for ln in f:
                try:
                    entries.append(json.loads(ln))
                except:
                    continue
    entries = sorted(entries, key=lambda e: e.get("ts", 0), reverse=True)
    return jsonify({"ok": True, "history": entries})


@app.route("/api/honeypot/auto_retrain", methods=["POST"])
def api_honeypot_auto_retrain():
    """Enable/disable auto retrain. Body: {'enable': true/false}"""
    global auto_retrain_enabled
    data = request.get_json() or {}
    enable = bool(data.get("enable", False))
    auto_retrain_enabled = enable
    entry = {"ts": time.time(), "action": "auto_retrain_toggle", "enabled": enable}
    append_retrain_history(entry)
    return jsonify({"ok": True, "auto_retrain": auto_retrain_enabled})


# ------------ Background watcher: watches honeypot log and triggers retrain -------------
def honeypot_watcher_loop(poll_interval=6):
    """Watch HONEYPOT_LOG mtime; when changed and auto_retrain_enabled -> trigger retrain."""
    global _last_honeypot_mtime
    while True:
        try:
            if HONEYPOT_LOG.exists():
                m = HONEYPOT_LOG.stat().st_mtime
                if m != _last_honeypot_mtime:
                    # new activity
                    _last_honeypot_mtime = m
                    logger.info("[watcher] honeypot log changed, mtime=%s", m)
                    if auto_retrain_enabled:
                        # trigger retrain (non-blocking)
                        logger.info("[watcher] auto_retrain enabled -> triggering retrain")
                        try:
                            cmd = [sys.executable, "-m", "honeypot.trainer.retrain"]
                            stdout_f = open(RETRAIN_LOG, "a")
                            stderr_f = open(RETRAIN_LOG, "a")
                            p = subprocess.Popen(cmd, cwd=str(ROOT), stdout=stdout_f, stderr=stderr_f, env=os.environ)
                            append_retrain_history({"ts": time.time(), "action": "auto_retrain_trigger", "pid": p.pid})
                        except Exception as e:
                            logger.exception("[watcher] failed to auto start retrain: %s", e)
            time.sleep(poll_interval)
        except Exception as e:
            logger.exception("[watcher] exception: %s", e)
            time.sleep(poll_interval)


# start watcher thread on startup
watcher_thread = threading.Thread(target=honeypot_watcher_loop, daemon=True)
watcher_thread.start()


# ------------ Existing endpoints (events, blocks, etc) -------------
def read_events(last_n=500):
    """
    Return normalized events list from logs/events.json
    Each event will be in the shape:
      { timestamp: ISO str, ip: str, score: float|null, decision: "NORMAL"/"SUSPICIOUS"/"BLOCKED", ... }
    """
    events = []
    if not EVENTS_JSON.exists():
        return events
    with open(EVENTS_JSON, "r") as f:
        lines = f.readlines()
    lines = lines[-last_n:]
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            raw = json.loads(ln)
        except json.JSONDecodeError:
            continue
        try:
            events.append(normalize_event(raw))
        except Exception:
            # fallback minimal mapping
            events.append({
                "timestamp": datetime.utcnow().isoformat(),
                "ip": raw.get("ip") or raw.get("src_ip"),
                "score": raw.get("score"),
                "decision": (raw.get("decision") or raw.get("label") or "NORMAL").upper()
            })
    return events


def get_blocked_from_iptables():
    try:
        out = subprocess.check_output(shlex.split("iptables -S"), stderr=subprocess.STDOUT).decode()
        blocked = []
        for line in out.splitlines():
            if "-j DROP" in line and "AIAF:" in line:
                parts = line.split()
                ip = None
                if "-s" in parts:
                    idx = parts.index("-s")
                    if idx + 1 < len(parts):
                        ip = parts[idx + 1]
                blocked.append({"rule": line, "ip": ip})
        return blocked
    except Exception as e:
        logger.warning("Could not fetch iptables rules: %s", e)
        rows = []
        for rid, (cmd, exp) in getattr(rule_mgr, "active_rules", {}).items():
            rows.append({"rule_id": rid, "cmd": cmd, "expire_at": exp})
        return rows


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    last_n = int(request.args.get("n", 500))
    events = read_events(last_n=last_n)
    # return as {ok, events} for frontend compatibility
    return jsonify({"ok": True, "events": events})


@app.route("/api/blocks")
def api_blocks():
    blocks = get_blocked_from_iptables()
    return jsonify({"ok": True, "blocks": blocks})


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json() or {}
    rule_id = data.get("rule_id")
    ip = data.get("ip")

    if not rule_id and not ip:
        return jsonify({"ok": False, "error": "provide rule_id or ip"}), 400

    if rule_id and rule_id in getattr(rule_mgr, "active_rules", {}):
        rule_mgr.remove_rule(rule_id)
        return jsonify({"ok": True, "removed": rule_id})

    if ip:
        try:
            out = subprocess.check_output(shlex.split("iptables -S"), stderr=subprocess.STDOUT).decode()
            deleted = []
            for line in out.splitlines():
                if ip in line and "AIAF:" in line:
                    del_line = line.replace("-A", "-D", 1)
                    cmd = "iptables " + del_line
                    subprocess.check_call(cmd, shell=True)
                    deleted.append(del_line)
            return jsonify({"ok": True, "deleted": deleted})
        except Exception as e:
            logger.exception("Failed to delete iptables rule: %s", e)
            return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": False, "error": "not found"}), 404


# static files
@app.route("/static/<path:p>")
def static_proxy(p):
    return send_from_directory(app.static_folder, p)


if __name__ == "__main__":
    # auto-start honeypot on dashboard startup (safe: dry-run flag doesn't affect honeypot)
    try:
        # start honeypot only if not running already
        with honeypot_lock:
            if not (honeypot_proc and honeypot_proc.poll() is None):
                os.makedirs(HONEYPOT_LOG.parent, exist_ok=True)
                cmd = [sys.executable, str(ROOT / "honeypot" / "honeypot_server.py")]
                stdout_f = open(HONEYPOT_STDOUT, "a")
                stderr_f = open(HONEYPOT_STDERR, "a")
                honeypot_proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=stdout_f, stderr=stderr_f, env=os.environ)
                logger.info("Auto-started honeypot pid=%s", honeypot_proc.pid)
    except Exception as e:
        logger.exception("Failed auto-start honeypot: %s", e)

    logger.info(f"Starting dashboard on {DASHBOARD_HOST}:{DASHBOARD_PORT} (dry_run={DASHBOARD_DRY_RUN})")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)
