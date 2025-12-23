import os
import sys
import json
import hashlib
import time
import subprocess
from datetime import datetime

# --- Constants & Identity ---
TOOL_NAME = "IRONCLAD"
VERSION = "4.0.0"
AUTHOR = "Syed Sameer ul Hassan"
WEBSITE = "sameer.orildo.online"
EMAIL = "sameer@orildo.online"

SEVERITY_WEIGHTS = {
    "INFO": 0, "LOW": 1, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 25
}

class Finding:
    def __init__(self, rule_id, module, severity, message, remediation):
        self.rule_id = rule_id
        self.module = module
        self.severity = severity
        self.message = message
        self.remediation = remediation
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self):
        return self.__dict__

class IroncladContext:
    def __init__(self, policy_data):
        self.policy = policy_data
        self.findings = []
        self.start_time = datetime.now()
        self.system_meta = {
            "hostname": os.uname().nodename,
            "kernel": os.uname().release,
            "scan_id": hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        }

    def register_finding(self, rule_id, module, default_severity, message, remediation):
        severity = default_severity
        if self.policy and rule_id in self.policy.get("rules", {}):
            severity = self.policy["rules"][rule_id].get("severity", default_severity)
        self.findings.append(Finding(rule_id, module, severity, message, remediation))

    def calculate_risk_score(self):
        score = 100
        for f in self.findings:
            penalty = SEVERITY_WEIGHTS.get(f.severity, 1)
            score -= penalty
        crit_count = sum(1 for f in self.findings if f.severity == "CRITICAL")
        if crit_count > 0: score = min(score, 50)
        return max(0, score)

class BaselineEngine:
    def __init__(self, baseline_path="ironclad_baseline.json"):
        self.path = baseline_path

    def _hash_file(self, filepath):
        if not os.path.exists(filepath): return "MISSING"
        sha = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(4096):
                    sha.update(chunk)
            return sha.hexdigest()
        except PermissionError:
            return "ACCESS_DENIED"

    def _hash_string(self, s):
        return hashlib.sha256(s.encode()).hexdigest()

    def capture(self):
        snapshot = {
            "timestamp": datetime.utcnow().isoformat(),
            "files": {
                "/etc/passwd": self._hash_file("/etc/passwd"),
                "/etc/shadow": self._hash_file("/etc/shadow"),
                "/etc/ssh/sshd_config": self._hash_file("/etc/ssh/sshd_config"),
                "/etc/sudoers": self._hash_file("/etc/sudoers")
            },
            "network": {
                "listening_ports": self._hash_string(subprocess.run(['ss', '-tuln'], capture_output=True, text=True).stdout)
            }
        }
        return snapshot

    def save(self):
        data = self.capture()
        with open(self.path, 'w') as f:
            json.dump(data, f, indent=2)
        return self.path

    def check_drift(self, current_context):
        if not os.path.exists(self.path): return
        try:
            with open(self.path, 'r') as f:
                old = json.load(f)
            new = self.capture()
            for fname, h in old["files"].items():
                if new["files"].get(fname) != h:
                    current_context.register_finding("DRIFT_FILE", "BASELINE", "HIGH", f"Configuration Drift: {fname} modified", "Investigate changes")
            if old["network"]["listening_ports"] != new["network"]["listening_ports"]:
                current_context.register_finding("DRIFT_NET", "BASELINE", "MEDIUM", "Network Profile Changed", "Review active services")
        except Exception as e:
            current_context.register_finding("DRIFT_ERR", "BASELINE", "INFO", f"Baseline check failed: {str(e)}", "")
