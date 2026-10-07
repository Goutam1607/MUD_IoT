"""
====================================================================
BENCHMARK SCRIPT - Measures REAL performance of the MUD framework
Run this once, screenshot/save the output, use these numbers in
the paper's Tables IV, V, VI, VII. No fabricated numbers.
====================================================================
"""
import sys
import os
import time
import socket
import statistics
import subprocess

os.chdir('mud_manager')
sys.path.insert(0, os.getcwd())

from mud_manager import fetch_mud_file, parse_mud_rules, verify_signature
from rule_enforcer import flush_rules, apply_rule
import requests

RUNS = 10  # number of repetitions per measurement, for a fair average

print("=" * 70)
print("MUD FRAMEWORK - PERFORMANCE BENCHMARK")
print(f"Each metric measured over {RUNS} runs, average + std dev reported")
print("=" * 70)

# ============================================================
# 1. DEVICE DETECTION TIME (ARP scan duration)
# ============================================================
print("\n[1/4] Measuring device detection time (ARP scan)...")
sys.path.append('.')
from device_detector import scan_network, get_current_subnet

subnet = get_current_subnet("wlan0")
detection_times = []
for i in range(RUNS):
    start = time.perf_counter()
    scan_network(subnet)
    elapsed_ms = (time.perf_counter() - start) * 1000
    detection_times.append(elapsed_ms)
    print(f"   Run {i+1}: {elapsed_ms:.1f} ms")

print(f"   >>> AVERAGE: {statistics.mean(detection_times):.1f} ms "
      f"(std dev: {statistics.stdev(detection_times):.1f} ms)")

# ============================================================
# 2. RSA SIGNATURE VERIFICATION TIME
# ============================================================
print("\n[2/4] Measuring RSA-2048 signature verification time...")
mud_url = "http://localhost:5000/mud/temperature_sensor.json"
response = requests.get(mud_url, timeout=10)
raw_bytes = response.content
signature = response.headers.get('X-MUD-Signature')

verify_times = []
for i in range(RUNS):
    start = time.perf_counter()
    verify_signature(raw_bytes, signature)
    elapsed_ms = (time.perf_counter() - start) * 1000
    verify_times.append(elapsed_ms)
    print(f"   Run {i+1}: {elapsed_ms:.2f} ms")

print(f"   >>> AVERAGE: {statistics.mean(verify_times):.2f} ms "
      f"(std dev: {statistics.stdev(verify_times):.2f} ms)")

# ============================================================
# 3. POLICY PARSING + RULE GENERATION + INSTALLATION TIME
# ============================================================
print("\n[3/4] Measuring parsing / rule generation / installation time...")

parse_times = []
install_times = []

for i in range(RUNS):
    # Parsing: JSON -> rule objects
    start = time.perf_counter()
    mud_file = response.json()
    rules = parse_mud_rules(mud_file)
    parse_elapsed_ms = (time.perf_counter() - start) * 1000
    parse_times.append(parse_elapsed_ms)

    # Installation: rule objects -> real iptables commands via subprocess
    flush_rules()
    start = time.perf_counter()
    for rule in rules:
        apply_rule(action=rule["action"], dst_ip=rule["dst"], port=rule["port"])
    install_elapsed_ms = (time.perf_counter() - start) * 1000
    install_times.append(install_elapsed_ms)

    print(f"   Run {i+1}: parse={parse_elapsed_ms:.2f} ms, "
          f"install={install_elapsed_ms:.2f} ms")

avg_parse = statistics.mean(parse_times)
avg_install = statistics.mean(install_times)
avg_total = avg_parse + avg_install

print(f"   >>> AVERAGE Parsing: {avg_parse:.2f} ms")
print(f"   >>> AVERAGE Installation: {avg_install:.2f} ms")
print(f"   >>> AVERAGE Total: {avg_total:.2f} ms")

# ============================================================
# 4. ATTACK BLOCKING RATE (many trials, real ports)
# ============================================================
print("\n[4/4] Measuring attack blocking rate (real firewall)...")

ATTACK_PORTS = {
    "SSH": 22,
    "Telnet": 23,
    "FTP": 21,
    "HTTP": 80,
    "MySQL": 3306,
    "HTTP-alt/C2": 8080,
}
TRIALS_PER_PORT = 20

def try_connect(dst, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((dst, port))
        s.close()
        return result == 0
    except:
        return False

blocking_results = {}
for attack_name, port in ATTACK_PORTS.items():
    blocked_count = 0
    for _ in range(TRIALS_PER_PORT):
        connected = try_connect("127.0.0.1", port)
        if not connected:
            blocked_count += 1
    blocking_rate = (blocked_count / TRIALS_PER_PORT) * 100
    blocking_results[attack_name] = blocking_rate
    print(f"   {attack_name:15s} port {port:5d}: {blocked_count}/{TRIALS_PER_PORT} blocked "
          f"({blocking_rate:.1f}%)")

overall_avg = statistics.mean(blocking_results.values())
print(f"   >>> AVERAGE BLOCKING RATE: {overall_avg:.1f}%")

# ============================================================
# FINAL SUMMARY (paste-ready for paper tables)
# ============================================================
print("\n" + "=" * 70)
print("SUMMARY - READY FOR PAPER TABLES")
print("=" * 70)
print(f"Table IV  - Device Detection Time:      {statistics.mean(detection_times):.1f} ms")
print(f"Table V   - Signature Verification Time: {statistics.mean(verify_times):.2f} ms")
print(f"Table VI  - Policy Parsing Time:         {avg_parse:.2f} ms")
print(f"Table VI  - Rule Installation Time:      {avg_install:.2f} ms")
print(f"Table VI  - Total Enforcement Time:      {avg_total:.2f} ms")
print(f"Table VII - Average Blocking Rate:       {overall_avg:.1f}%")
print("=" * 70)
