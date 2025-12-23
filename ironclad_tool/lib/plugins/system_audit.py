import os
def audit(ctx):
    ssh_conf = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_conf):
        cfg = {}
        try:
            with open(ssh_conf) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key = parts[0].lower()
                        if key not in cfg: cfg[key] = parts[1]
            
            if cfg.get('permitrootlogin', 'prohibit-password').lower() == 'yes':
                ctx.register_finding("SSH_ROOT_LOGIN", "SSH", "CRITICAL", "Root Login ENABLED", "Set PermitRootLogin no")
            if cfg.get('passwordauthentication', 'yes').lower() == 'yes':
                ctx.register_finding("SSH_PASS_AUTH", "SSH", "HIGH", "Password Auth ENABLED", "Set PasswordAuthentication no")
        except: pass

    try:
        with open('/etc/passwd') as f:
            for line in f:
                parts = line.split(':')
                if len(parts) > 2 and parts[2] == '0' and parts[0] != 'root':
                    ctx.register_finding("UID_0_CHECK", "IAM", "CRITICAL", f"Backdoor User (UID 0): {parts[0]}", "Delete user immediately")
    except: pass
