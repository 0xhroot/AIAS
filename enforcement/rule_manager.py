# enforcement/rule_manager.py
import subprocess
import shlex
import time
import logging
import os
from utils.logger import get_logger

logger = get_logger('rule_manager')

class RuleManager:
    def __init__(self, dry_run=True):
        """
        dry_run: if True, will not execute iptables commands; only print/log them.
        """
        self.dry_run = dry_run
        # store active rules for TTL cleanup: {rule_id: (cmd, expire_ts)}
        self.active_rules = {}

    def _exec(self, cmd):
        logger.info(f"Exec: {cmd}")
        if self.dry_run:
            return (0, "dry-run", "")
        try:
            output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
            return (0, output.decode('utf-8'), "")
        except subprocess.CalledProcessError as e:
            return (e.returncode, e.output.decode('utf-8'), str(e))

    def add_block_ip(self, ip, ttl_seconds=3600, reason='auto'):
        """
        Add a DROP rule for src ip. TTL management is local: caller must call cleanup_expired periodically.
        """
        rule = f"iptables -I INPUT -s {ip} -j DROP -m comment --comment \"AIAF:{reason}\""
        code, out, err = self._exec(rule)
        rule_id = f"{ip}-{int(time.time())}"
        self.active_rules[rule_id] = (rule, time.time() + ttl_seconds)
        logger.info(f"Added block for {ip} (ttl={ttl_seconds}s), rule_id={rule_id}")
        return rule_id

    def remove_rule(self, rule_id):
        if rule_id not in self.active_rules:
            logger.warning("rule_id not found: " + str(rule_id))
            return False
        rule, _ = self.active_rules.pop(rule_id)
        # iptables removal is tricky; for dry-run we skip. For production you should compute exact deletion.
        # Here we'll log removal; in real deployment you'd save the inserted rule line number or use iptables-save/restore.
        logger.info(f"Removing rule ({rule_id}): {rule}")
        return True

    def cleanup_expired(self):
        now = time.time()
        expired = [rid for rid,(r,exp) in self.active_rules.items() if exp <= now]
        for rid in expired:
            self.remove_rule(rid)
