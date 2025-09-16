# enforcement/rule_manager.py
import os
import shlex
import subprocess
import threading
import time
from typing import Optional
from utils.logger import logger

class RuleManager:
    def __init__(self, dry_run: bool = True, whitelist=None):
        self.dry_run = dry_run
        self.active_rules = {}  # rule_id -> (cmd, expire_ts)
        self.lock = threading.Lock()
        self.whitelist = set(whitelist or [])
        # spawn cleanup thread
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()

    def _exec(self, cmd: str) -> bool:
        logger.info(f"[rule_manager] Exec: {cmd}")
        if self.dry_run:
            # simulate and store
            return True
        try:
            subprocess.check_call(shlex.split(cmd))
            return True
        except subprocess.CalledProcessError as e:
            logger.exception("[rule_manager] iptables command failed: %s", e)
            return False

    def block_ip(self, ip: str, reason: str = "auto_block", ttl: int = 3600) -> Optional[str]:
        """Insert a DROP rule and record it (returns rule_id)."""
        if ip in self.whitelist:
            logger.info("[rule_manager] skip block, ip whitelisted: %s", ip)
            return None
        rule_id = f"block-{ip}-{int(time.time())}"
        cmd = f"iptables -I INPUT -s {ip} -j DROP -m comment --comment \"AIAF:{reason}\""
        ok = self._exec(cmd)
        if ok:
            expire = time.time() + ttl
            with self.lock:
                self.active_rules[rule_id] = (cmd, expire)
            logger.info("[rule_manager] Added block for %s (ttl=%ds) rule_id=%s", ip, ttl, rule_id)
            return rule_id
        return None

    def redirect_to_honeypot(self, src_ip: str, honeypot_ip: str, honeypot_port: int = 2222,
                             reason: str = "honeypot_redirect", ttl: int = 3600) -> Optional[str]:
        """
        DNAT incoming traffic from src_ip to honeypot_ip:honeypot_port (PREROUTING NAT).
        Note: host must be gateway or see traffic. Caller should ensure whitelist.
        """
        if src_ip in self.whitelist:
            logger.info("[rule_manager] skip redirect, ip whitelisted: %s", src_ip)
            return None

        rule_id = f"redir-{src_ip}-{int(time.time())}"
        # enable forwarding if not in dry-run
        if not self.dry_run:
            try:
                subprocess.check_call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            except Exception as e:
                logger.warning("[rule_manager] failed to set ip_forward: %s", e)

        # Insert NAT rule: match source IP to dport, DNAT to honeypot
        cmd = (f"iptables -t nat -I PREROUTING -s {src_ip} -p tcp "
               f"--dport {honeypot_port} -j DNAT --to-destination {honeypot_ip}:{honeypot_port} "
               f"-m comment --comment \"AIAF:{reason}\"")
        ok = self._exec(cmd)
        if ok:
            expire = time.time() + ttl
            with self.lock:
                self.active_rules[rule_id] = (cmd, expire)
            logger.info("[rule_manager] Redirected %s -> %s:%d rule_id=%s", src_ip, honeypot_ip, honeypot_port, rule_id)
            return rule_id
        return None

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a previously recorded rule by converting -I/-A to -D or using stored line."""
        with self.lock:
            entry = self.active_rules.get(rule_id)
            if not entry:
                logger.warning("[rule_manager] remove_rule: unknown rule_id %s", rule_id)
                return False
            cmd, _ = entry

        # naive conversion: exchange "-I" or "-A" with "-D"
        del_cmd = cmd
        if cmd.startswith("iptables "):
            del_cmd = cmd.replace("-I ", "-D ", 1).replace("-A ", "-D ", 1)
        else:
            del_cmd = "iptables " + cmd.replace("-I ", "-D ", 1)

        ok = True
        if not self.dry_run:
            try:
                subprocess.check_call(shlex.split(del_cmd))
            except subprocess.CalledProcessError as e:
                logger.exception("[rule_manager] failed to delete rule: %s", e)
                ok = False

        if ok:
            with self.lock:
                if rule_id in self.active_rules:
                    del self.active_rules[rule_id]
            logger.info("[rule_manager] Removed rule %s", rule_id)
            return True
        return False

    def _cleanup_loop(self):
        while True:
            now = time.time()
            to_remove = []
            with self.lock:
                for rid, (cmd, exp) in list(self.active_rules.items()):
                    if exp and now > exp:
                        to_remove.append(rid)
            for rid in to_remove:
                try:
                    self.remove_rule(rid)
                except Exception as e:
                    logger.warning("[rule_manager] cleanup failed for %s: %s", rid, e)
            time.sleep(30)

