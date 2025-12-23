import subprocess
def audit(ctx):
    active = False
    try:
        if "Status: active" in subprocess.run("ufw status".split(), capture_output=True, text=True).stdout: active = True
        if "running" in subprocess.run("firewall-cmd --state".split(), capture_output=True, text=True).stdout: active = True
        if not active:
             if len(subprocess.run("iptables -L -n".split(), capture_output=True, text=True).stdout.splitlines()) > 5: active = True
    except: pass

    if not active:
        ctx.register_finding("FW_ACTIVE", "NETWORK", "CRITICAL", "No Active Firewall Found", "Enable UFW or Firewalld")

    try:
        ports = subprocess.run("ss -tuln".split(), capture_output=True, text=True).stdout
        if ":23 " in ports:
            ctx.register_finding("PORT_TELNET", "NETWORK", "HIGH", "Telnet Detected (Port 23)", "Disable telnetd")
    except: pass
