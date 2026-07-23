import subprocess
from colorama import Fore

CHAIN = "INPUT"

def apply_rule(action, dst_ip, port, protocol="tcp"):
    jump_target = "ACCEPT" if action == "accept" else "DROP"
    cmd = ["sudo", "iptables", "-A", CHAIN, "-p", protocol]
    if port != "any":
        cmd += ["--dport", str(port)]
    if dst_ip not in ("any", "0.0.0.0/0"):
        cmd += ["-d", dst_ip]
    cmd += ["-j", jump_target]
    print(f"{Fore.YELLOW}[ENFORCER] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"{Fore.GREEN}[ENFORCER] Rule applied successfully.")
    else:
        print(f"{Fore.RED}[ENFORCER] Failed to apply rule: {result.stderr}")

def flush_rules():
    print(f"{Fore.YELLOW}[ENFORCER] Flushing existing rules on chain {CHAIN}...")
    subprocess.run(["sudo", "iptables", "-F", CHAIN])

def apply_all_rules(rules):
    flush_rules()
    # Allow loopback (local Pi processes talking to each other)
    subprocess.run(["sudo","iptables","-A","INPUT","-i","lo","-j","ACCEPT"], capture_output=True)
    # Allow established/related connections (response packets)
    subprocess.run(["sudo","iptables","-A","INPUT","-m","conntrack","--ctstate","ESTABLISHED,RELATED","-j","ACCEPT"], capture_output=True)
    print("[ENFORCER] Standard rules added (loopback + established connections)")
    for rule in rules:
        apply_rule(action=rule["action"], dst_ip=rule["dst"], port=rule["port"])
    print(f"{Fore.CYAN}[ENFORCER] All {len(rules)} MUD rules pushed to the real firewall.")


