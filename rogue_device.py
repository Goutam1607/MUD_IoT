import socket
import time

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

CONNECTIONS = [
    {"dst": "localhost",       "port": 1883, "desc": "MQTT to broker (legitimate sensor traffic)",   "expect": "ALLOWED",  "reason": "MUD policy ALLOWS port 1883 — this is what DHT11 sensor uses"},
    {"dst": "8.8.8.8",        "port": 443,  "desc": "HTTPS firmware update to Google DNS",          "expect": "ALLOWED",  "reason": "MUD policy ALLOWS port 443 for firmware updates"},
    {"dst": "1.1.1.1",        "port": 80,   "desc": "HTTP to Cloudflare (data exfiltration attempt)","expect": "BLOCKED", "reason": "MUD policy has no rule for port 80 — default deny"},
    {"dst": "142.250.182.46", "port": 22,   "desc": "SSH to Google server (botnet C&C attempt)",    "expect": "BLOCKED",  "reason": "MUD policy has no rule for port 22 — default deny"},
    {"dst": "52.84.0.1",      "port": 23,   "desc": "Telnet to Amazon AWS (Mirai-style attack)",    "expect": "BLOCKED",  "reason": "MUD policy has no rule for port 23 — default deny"},
    {"dst": "91.108.4.1",     "port": 3306, "desc": "MySQL to external server (DB exfiltration)",   "expect": "BLOCKED",  "reason": "MUD policy has no rule for port 3306 — default deny"},
    {"dst": "104.21.0.1",     "port": 8080, "desc": "HTTP-alt to Cloudflare (C2 server callback)",  "expect": "BLOCKED",  "reason": "MUD policy has no rule for port 8080 — default deny"},
    {"dst": "8.8.8.8",        "port": 53,   "desc": "DNS over TCP to Google (DNS tunneling attack)", "expect": "BLOCKED", "reason": "MUD policy has no rule for port 53 TCP — default deny"},
]

def try_connect(dst, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((dst, port))
        s.close()
        return result == 0
    except:
        return False

print(f"\n{BOLD}{'='*65}{RESET}")
print(f"{BOLD}  ROGUE DEVICE — REAL TCP CONNECTION ATTEMPTS{RESET}")
print(f"{BOLD}  Simulating a compromised DHT11 sensor making attack traffic{RESET}")
print(f"{BOLD}{'='*65}{RESET}\n")

passed = 0
failed = 0

for i, conn in enumerate(CONNECTIONS, 1):
    dst    = conn["dst"]
    port   = conn["port"]
    desc   = conn["desc"]
    expect = conn["expect"]
    reason = conn["reason"]

    print(f"  [{i}] {BOLD}{desc}{RESET}")
    print(f"       Target : {dst}:{port}")
    print(f"       Policy : {reason}")
    print(f"       Result :", end=" ", flush=True)

    connected = try_connect(dst, port)
    actual    = "ALLOWED" if connected else "BLOCKED"

    if actual == expect == "ALLOWED":
        print(f"{GREEN}CONNECTED — MUD ALLOWS this ✓{RESET}")
        passed += 1
    elif actual == expect == "BLOCKED":
        print(f"{RED}BLOCKED by iptables — MUD DENIES this ✓{RESET}")
        passed += 1
    elif actual == "ALLOWED" and expect == "BLOCKED":
        print(f"{YELLOW}WARNING: Connected but should be BLOCKED{RESET}")
        failed += 1
    else:
        print(f"{YELLOW}WARNING: Blocked but expected ALLOWED{RESET}")
        failed += 1
    print()
    time.sleep(0.5)

print(f"{BOLD}{'='*65}{RESET}")
if failed == 0:
    print(f"  {GREEN}{BOLD}ALL {passed} RESULTS CORRECT — MUD enforcement working!{RESET}")
else:
    print(f"  {GREEN}{passed} correct{RESET}  |  {YELLOW}{failed} unexpected — check iptables{RESET}")
print(f"{BOLD}{'='*65}{RESET}\n")
