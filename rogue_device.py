import socket
import time

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PI_IP      = "10.211.83.196"
GATEWAY_IP = "10.211.83.201"

CONNECTIONS = [
    {"dst": PI_IP,      "port": 1883, "desc": "MQTT to Pi broker",            "expect": "ALLOWED"},
    {"dst": "8.8.8.8",  "port": 443,  "desc": "HTTPS firmware update",        "expect": "ALLOWED"},
    {"dst": GATEWAY_IP, "port": 80,   "desc": "HTTP to phone gateway",         "expect": "BLOCKED"},
    {"dst": GATEWAY_IP, "port": 22,   "desc": "SSH attack to gateway",         "expect": "BLOCKED"},
    {"dst": "8.8.8.8",  "port": 23,   "desc": "Telnet to internet",            "expect": "BLOCKED"},
    {"dst": GATEWAY_IP, "port": 3306, "desc": "MySQL DB access attempt",       "expect": "BLOCKED"},
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

print(f"\n{BOLD}{'='*62}{RESET}")
print(f"{BOLD}  ROGUE DEVICE — REAL TCP CONNECTION ATTEMPTS{RESET}")
print(f"{BOLD}  Pi: {PI_IP}  |  Gateway: {GATEWAY_IP}{RESET}")
print(f"{BOLD}{'='*62}{RESET}\n")

passed = 0
failed = 0

for i, conn in enumerate(CONNECTIONS, 1):
    dst    = conn["dst"]
    port   = conn["port"]
    desc   = conn["desc"]
    expect = conn["expect"]

    print(f"  [{i}] {BOLD}{desc}{RESET}")
    print(f"      Target: {dst}:{port}")
    print(f"      Connecting...", end=" ", flush=True)

    connected = try_connect(dst, port)
    actual    = "ALLOWED" if connected else "BLOCKED"

    if actual == expect == "ALLOWED":
        print(f"{GREEN}CONNECTED — MUD ALLOWS this ✓{RESET}")
        passed += 1
    elif actual == expect == "BLOCKED":
        print(f"{RED}BLOCKED by iptables — MUD DENIES this ✓{RESET}")
        passed += 1
    elif actual == "ALLOWED" and expect == "BLOCKED":
        print(f"{YELLOW}WARNING: Connected but should be BLOCKED — apply MUD rules first!{RESET}")
        failed += 1
    else:
        print(f"{YELLOW}WARNING: Blocked but expected ALLOWED{RESET}")
        failed += 1
    print()
    time.sleep(0.5)

print(f"{BOLD}{'='*62}{RESET}")
if failed == 0:
    print(f"  {GREEN}{BOLD}ALL {passed} RESULTS CORRECT — MUD enforcement working!{RESET}")
else:
    print(f"  {passed} correct  |  {YELLOW}{failed} unexpected — check iptables{RESET}")
print(f"{BOLD}{'='*62}{RESET}\n")
