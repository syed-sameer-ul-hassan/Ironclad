#!/usr/bin/env python3
import argparse
import sys
import os
import json
import time
from datetime import datetime

# Add lib to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))

from core import IroncladContext, BaselineEngine
from plugins import PluginManager
import reporting

def load_policy(path):
    if not path: return {}
    try:
        with open(path) as f: return json.load(f)
    except Exception as e:
        print(f"Error loading policy: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="IRONCLAD Enterprise Security Tool")
    parser.add_argument("--json", action="store_true", help="Output JSON for SIEM")
    parser.add_argument("--policy", help="Path to policy JSON file", default=None)
    parser.add_argument("--baseline-update", action="store_true", help="Update the security baseline")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous monitoring mode")
    parser.add_argument("--interval", type=int, default=3600, help="Daemon scan interval in seconds")
    
    args = parser.parse_args()

    # Default policy path relative to script
    if not args.policy:
        base_path = os.path.dirname(__file__)
        args.policy = os.path.join(base_path, "policies", "cis_server_l1.json")

    # Safety Check
    if os.geteuid() != 0:
        if not args.json:
            print("IRONCLAD requires root privileges to audit secure configurations.")
        sys.exit(1)

    # 1. Baseline Management
    baseline = BaselineEngine()
    if args.baseline_update:
        path = baseline.save()
        print(f"Baseline updated successfully at {path}")
        sys.exit(0)

    # 2. Execution Logic
    policy_data = load_policy(args.policy)
    
    def run_scan():
        ctx = IroncladContext(policy_data)
        baseline.check_drift(ctx)
        PluginManager.run_all(ctx)
        return ctx

    # 3. Daemon Mode
    if args.daemon:
        print(f"[*] IRONCLAD Daemon started. Interval: {args.interval}s")
        while True:
            ctx = run_scan()
            if ctx.calculate_risk_score() < 80:
                print(f"[{datetime.now()}] ALERT: Low Security Score ({ctx.calculate_risk_score()})")
            time.sleep(args.interval)

    # 4. Standard Run
    ctx = run_scan()
    
    if args.json:
        reporting.render_json(ctx)
    else:
        reporting.render_console(ctx)

if __name__ == "__main__":
    main()
