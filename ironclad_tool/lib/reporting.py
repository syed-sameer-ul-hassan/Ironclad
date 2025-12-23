import json
import sys
from .core import TOOL_NAME, VERSION, AUTHOR, WEBSITE, EMAIL

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

def print_banner():
    print(f"""{CYAN}{BOLD}
   ___ ___  ___  _  _  ___ _      _   ___ 
  |_ _| _ \/ _ \| \| |/ __| |    /_\ |   \\
   | ||   / (_) | .` | (__| |__ / _ \| |) |
  |___|_|_\\\___/|_|\_|\___|____/_/ \_\___/ 
    {RESET}""")
    print(f"  {BOLD}Version:{RESET} {VERSION} | {BOLD}Author:{RESET} {AUTHOR}")
    print(f"  {BOLD}Web:{RESET} {WEBSITE} | {BOLD}Contact:{RESET} {EMAIL}")
    print(f"{CYAN}============================================={RESET}")

def render_console(context):
    print_banner()
    score = context.calculate_risk_score()
    s_color = GREEN if score > 80 else (YELLOW if score > 50 else RED)
    
    print(f"\n{BOLD}SYSTEM RISK SCORE: {s_color}{score}/100{RESET}")
    print(f"Findings: {len(context.findings)}")
    print("-" * 50)
    
    sorted_findings = sorted(context.findings, key=lambda x: {"CRITICAL":0, "HIGH":1, "MEDIUM":2, "LOW":3, "INFO":4}.get(x.severity, 5))
    
    for f in sorted_findings:
        c = {"CRITICAL": RED+BOLD, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN, "INFO": CYAN}.get(f.severity, RESET)
        print(f"[{c}{f.severity:<8}{RESET}] {BOLD}{f.module:<8}{RESET} : {f.message}")
        if f.severity in ["CRITICAL", "HIGH"]:
            print(f"             └── {CYAN}Remediation: {f.remediation}{RESET}")
    print("-" * 50)
    sys.exit(1 if score < 100 else 0)

def render_json(context):
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "meta": context.system_meta,
        "risk_score": context.calculate_risk_score(),
        "findings": [f.to_dict() for f in context.findings]
    }
    print(json.dumps(output, indent=2))
    sys.exit(1 if context.findings else 0)
