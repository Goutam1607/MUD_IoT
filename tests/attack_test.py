#!/usr/bin/env python3
"""
attack_test.py - Enforcement accuracy test for the MUD gateway (Gap 5.6)

Runs on the LAPTOP (Windows or Linux), connected to the MUD_Gateway WiFi.
Uses only the Python standard library - nothing to install.

What it does
------------
It fires a fixed list of connection attempts and records, for each one,
whether the packet got through (REACHED) or was silently dropped (BLOCKED).

Two groups of tests:
  A. EAST-WEST  : laptop -> camera (10.42.0.17) on common attack ports.
                  The camera's MUD file says "to-device: deny all",
                  so every one of these MUST be blocked.
  B. AS-CAMERA  : the laptop pretends to be a (compromised) camera.
                  The Pi runs gateway_enforcer.py for the laptop's IP with
                  the SAME ip_camera.json, so the laptop gets exactly the
                  camera's policy. Destinations the MUD file allows MUST
                  pass; everything else MUST be blocked.

How a result is decided
-----------------------
  TCP : connect OK or "connection refused" -> REACHED
        (refused = the far end answered with RST, so the packet got there)
        timeout                              -> BLOCKED (MUD uses DROP)
  UDP : we send a real request (DNS / STUN / NTP); a reply -> REACHED,
        no reply within the timeout -> BLOCKED
  ICMP: ping reply with a TTL -> REACHED, otherwise BLOCKED

Why two runs (baseline + enforced)?
-----------------------------------
A timeout can also mean "that server is just down". So we first run with
NO MUD rules (baseline). Only tests that REACHED in the baseline are
counted - if they are blocked later, MUD did it, not the internet.

Usage
-----
  python attack_test.py --label baseline       (MUD rules removed on Pi)
  python attack_test.py --label enforced       (MUD rules active on Pi)
  python attack_test.py --compare results_baseline.json results_enforced.json
"""

import argparse
import csv
import json
import os
import platform
import socket
import statistics
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

CAMERA_IP = "10.42.0.17"
TIMEOUT_S = 3.0          # how long to wait before calling a probe BLOCKED
TRIALS = 3               # attempts per test (majority vote decides)
GATEWAY_NET = "10.42.0." # the laptop MUST be sending from this network (MUD_Gateway)

# --------------------------------------------------------------------------
# TEST LIST
# (id, group, protocol, host, port, expected, reason)
#   expected = "PASS"  -> MUD file allows it, must get through
#   expected = "BLOCK" -> MUD file does not allow it, must be dropped
# --------------------------------------------------------------------------
TESTS = [
    # ---- A. East-west: laptop -> camera (to-device deny-all) ----
    ("A01", "east-west", "icmp", CAMERA_IP, 0,    "BLOCK", "ping camera"),
    ("A02", "east-west", "tcp",  CAMERA_IP, 21,   "BLOCK", "FTP to camera"),
    ("A03", "east-west", "tcp",  CAMERA_IP, 22,   "BLOCK", "SSH to camera"),
    ("A04", "east-west", "tcp",  CAMERA_IP, 23,   "BLOCK", "Telnet to camera (Mirai-style)"),
    ("A05", "east-west", "tcp",  CAMERA_IP, 80,   "BLOCK", "HTTP admin page"),
    ("A06", "east-west", "tcp",  CAMERA_IP, 443,  "BLOCK", "HTTPS admin page"),
    ("A07", "east-west", "tcp",  CAMERA_IP, 554,  "BLOCK", "RTSP video grab"),
    ("A08", "east-west", "tcp",  CAMERA_IP, 1883, "BLOCK", "MQTT"),
    ("A09", "east-west", "tcp",  CAMERA_IP, 6667, "BLOCK", "port 6667"),
    ("A10", "east-west", "tcp",  CAMERA_IP, 8000, "BLOCK", "alt web port"),
    ("A11", "east-west", "tcp",  CAMERA_IP, 8080, "BLOCK", "alt web port"),
    ("A12", "east-west", "tcp",  CAMERA_IP, 8886, "BLOCK", "camera cloud port, inbound"),

    # ---- B. Laptop acting as the camera: ALLOWED by ip_camera.json ----
    ("B01", "as-camera", "dns",  "8.8.8.8",                 53,   "PASS", "DNS to approved resolver"),
    ("B02", "as-camera", "tcp",  "m6-cube.cppluscloud.com", 8886, "PASS", "cloud control (dnsname rule)"),
    ("B03", "as-camera", "tcp",  "a6-cube.cppluscloud.com", 443,  "PASS", "cloud API (dnsname rule)"),
    ("B04", "as-camera", "stun", "stun.cloudflare.com",     3478, "PASS", "STUN, any destination"),
    ("B05", "as-camera", "tcp",  "portquiz.net",            1443, "PASS", "video relay port, any destination"),

    # ---- B. Laptop acting as the camera: NOT allowed -> must be blocked ----
    ("B06", "as-camera", "dns",  "1.1.1.1",                 53,   "BLOCK", "DNS to unapproved resolver"),
    ("B07", "as-camera", "tcp",  "1.1.1.1",                 443,  "BLOCK", "allowed port, wrong destination"),
    ("B08", "as-camera", "tcp",  "portquiz.net",            8886, "BLOCK", "allowed port, wrong destination"),
    ("B09", "as-camera", "tcp",  "portquiz.net",            80,   "BLOCK", "plain HTTP exfiltration"),
    ("B10", "as-camera", "tcp",  "portquiz.net",            22,   "BLOCK", "outbound SSH"),
    ("B11", "as-camera", "tcp",  "portquiz.net",            23,   "BLOCK", "outbound Telnet (botnet spread)"),
    ("B12", "as-camera", "tcp",  "portquiz.net",            4444, "BLOCK", "reverse shell port"),
    ("B13", "as-camera", "tcp",  "portquiz.net",            6667, "BLOCK", "IRC botnet C2"),
    ("B14", "as-camera", "tcp",  "portquiz.net",            3389, "BLOCK", "RDP"),
    ("B15", "as-camera", "tcp",  "portquiz.net",            8080, "BLOCK", "alt HTTP"),
    ("B16", "as-camera", "tcp",  "portquiz.net",            31337,"BLOCK", "backdoor port"),
    ("B17", "as-camera", "ntp",  "pool.ntp.org",            123,  "BLOCK", "NTP (not in MUD file)"),
]


# --------------------------------------------------------------------------
# PROBES - each returns (outcome, milliseconds)
# --------------------------------------------------------------------------
def probe_tcp(ip, port):
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT_S)
    try:
        s.connect((ip, port))
        return "REACHED", (time.perf_counter() - t0) * 1000
    except ConnectionRefusedError:
        # far end sent RST -> the packet DID get through the gateway
        return "REACHED", (time.perf_counter() - t0) * 1000
    except (socket.timeout, TimeoutError):
        return "BLOCKED", None
    except OSError:
        # e.g. "network unreachable" - treat as not delivered
        return "BLOCKED", None
    finally:
        s.close()


def udp_request(ip, port, payload, reply_ok):
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT_S)
    try:
        s.sendto(payload, (ip, port))
        data, _ = s.recvfrom(2048)
        if reply_ok(data):
            return "REACHED", (time.perf_counter() - t0) * 1000
        return "BLOCKED", None
    except (socket.timeout, TimeoutError, OSError):
        return "BLOCKED", None
    finally:
        s.close()


def probe_dns(ip, port):
    # Minimal DNS query: "A record for example.com"
    tid = os.urandom(2)
    header = tid + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3
    qname = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split(".")) + b"\x00"
    question = qname + b"\x00\x01\x00\x01"
    return udp_request(ip, port, header + question, lambda d: d[:2] == tid)


def probe_stun(ip, port):
    # STUN Binding Request (RFC 5389): type 0x0001, magic cookie 0x2112A442
    tx = os.urandom(12)
    msg = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + tx
    return udp_request(ip, port, msg, lambda d: len(d) >= 20 and d[8:20] == tx)


def probe_ntp(ip, port):
    # NTP client request: 48 bytes, first byte 0x1b (version 3, client mode)
    return udp_request(ip, port, b"\x1b" + b"\x00" * 47, lambda d: len(d) >= 48)


def probe_icmp(ip, port):
    t0 = time.perf_counter()
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(TIMEOUT_S * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(TIMEOUT_S)), ip]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    # Windows prints "Destination host unreachable" with exit code 0,
    # so only a line containing a TTL counts as a real reply.
    if "ttl=" in out.lower():
        return "REACHED", (time.perf_counter() - t0) * 1000
    return "BLOCKED", None


PROBES = {"tcp": probe_tcp, "dns": probe_dns, "stun": probe_stun,
          "ntp": probe_ntp, "icmp": probe_icmp}


# --------------------------------------------------------------------------
# PATH CHECK - did this probe really leave through MUD_Gateway?
# --------------------------------------------------------------------------
def route_src(ip):
    """Ask the OS which local IP it would use to reach `ip`.
    A UDP 'connect' sends no packet; it only picks the route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def on_gateway(ip):
    src = route_src(ip)
    return src is not None and src.startswith(GATEWAY_NET), src


# --------------------------------------------------------------------------
# RUN
# --------------------------------------------------------------------------
def resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def run_one(test, ip):
    tid, group, proto, host, port, expected, reason = test
    trials = []
    for _ in range(TRIALS):
        if ip is None:
            trials.append(("NO_DNS", None))
            continue
        ok_before, _ = on_gateway(ip)
        outcome = PROBES[proto](ip, port)
        ok_after, _ = on_gateway(ip)
        # If the laptop was not routing via MUD_Gateway at the start or end
        # of the trial, the packet may have left through another network
        # (e.g. Windows auto-switching WiFi). Such a trial proves nothing.
        trials.append(outcome if (ok_before and ok_after) else ("OFFPATH", None))
    outcomes = [o for o, _ in trials]
    reached = outcomes.count("REACHED")
    valid = reached + outcomes.count("BLOCKED")
    if "NO_DNS" in outcomes:
        final = "NO_DNS"
    elif valid == 0:
        final = "OFFPATH"
    else:
        final = "REACHED" if reached > valid / 2 else "BLOCKED"
    times = [ms for o, ms in trials if ms is not None and o == "REACHED"]
    return {
        "id": tid, "group": group, "proto": proto, "host": host, "ip": ip,
        "port": port, "expected": expected, "reason": reason,
        "trials": outcomes, "reached_trials": reached, "valid_trials": valid,
        "offpath_trials": outcomes.count("OFFPATH"), "result": final,
        "median_ms": round(statistics.median(times), 1) if times else None,
    }


def run(label):
    print(f"\n=== MUD attack test - run '{label}' ===")
    ok, src = on_gateway("8.8.8.8")
    print(f"Laptop source IP toward the internet: {src}")
    if not ok:
        sys.exit(f"STOP: the laptop is not routing through MUD_Gateway ({GATEWAY_NET}x). "
                 "Connect to MUD_Gateway and disable other networks first.")
    print(f"Tests: {len(TESTS)}  x  {TRIALS} trials  |  timeout {TIMEOUT_S}s\n")

    # Resolve every hostname ONCE, before any probe starts.
    ips = {}
    for t in TESTS:
        host = t[3]
        if host not in ips:
            ips[host] = resolve(host)
            if ips[host] is None:
                print(f"  [warn] could not resolve {host}")

    enforced_run = "enf" in label.lower()
    if enforced_run:
        # canary: a connection the MUD file forbids. It must be blocked
        # BEFORE the run starts, otherwise the rules are not active yet.
        if probe_tcp("1.1.1.1", 443)[0] == "REACHED":
            sys.exit("STOP: 1.1.1.1:443 got through - MUD rules are not active on the Pi yet.")

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda t: run_one(t, ips[t[3]]), TESTS))
    took = time.perf_counter() - t0

    if enforced_run and probe_tcp("1.1.1.1", 443)[0] == "REACHED":
        print("\n!! INVALID RUN: the canary got through at the END of the run, so the MUD")
        print("!! rules were removed while the test was still running. Re-run it and only")
        print("!! remove ATK on the Pi AFTER this script prints 'Done'.")

    print(f"{'ID':4} {'PROTO':5} {'DESTINATION':26} {'PORT':>5}  {'EXPECT':6} {'RESULT':8} TRIALS")
    for r in results:
        dest = r["host"] if r["host"] == r["ip"] else f"{r['host'][:16]} ({r['ip']})"
        print(f"{r['id']:4} {r['proto']:5} {dest[:26]:26} {r['port']:>5}  "
              f"{r['expected']:6} {r['result']:8} {r['reached_trials']}/{r['valid_trials']} reached"
              + (f"  ({r['offpath_trials']} OFF-PATH)" if r['offpath_trials'] else ""))
    off = sum(r["offpath_trials"] for r in results)
    if off:
        print(f"\n!! {off} trial(s) left the laptop through ANOTHER network, not MUD_Gateway.")
        print("!! They are ignored. Check that Windows did not switch WiFi during the run.")

    meta = {"label": label, "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "trials": TRIALS, "timeout_s": TIMEOUT_S, "duration_s": round(took, 1)}
    jpath = f"results_{label}.json"
    with open(jpath, "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=2)
    cpath = f"results_{label}.csv"
    with open(cpath, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "group", "proto", "host", "ip", "port", "expected",
                    "result", "reached_trials", "valid_trials", "offpath_trials",
                    "median_ms", "reason"])
        for r in results:
            w.writerow([r["id"], r["group"], r["proto"], r["host"], r["ip"], r["port"],
                        r["expected"], r["result"], r["reached_trials"], r["valid_trials"],
                        r["offpath_trials"], r["median_ms"], r["reason"]])
    print(f"\nDone in {took:.1f}s. Saved {jpath} and {cpath}")

    # ---- sanity checks: catch a wrong Pi state before it spoils the numbers
    def res(tid):
        return next(r["result"] for r in results if r["id"] == tid)
    a_blocked = [r["id"] for r in results if r["group"] == "east-west" and r["result"] != "REACHED"]
    must_block = [r for r in results if r["group"] == "as-camera" and r["expected"] == "BLOCK"]
    if "base" in label.lower():
        bad = [r["id"] for r in results if r["result"] != "REACHED"]
        if a_blocked:
            print("\n!! BASELINE PROBLEM: the camera was unreachable. CAM rules are probably")
            print("!! still installed on the Pi. Remove them and run the baseline again.")
        elif bad:
            print(f"\n!! BASELINE WARNING: {', '.join(bad)} did not get through without MUD.")
            print("!! Wait a minute and run the baseline again before continuing.")
        else:
            print("\nBaseline OK: all 29 tests got through with no MUD rules.")
    if "enf" in label.lower():
        if must_block and all(r["result"] == "REACHED" for r in must_block) and not a_blocked:
            print("\n!! ENFORCED PROBLEM: nothing was blocked at all. The MUD rules are NOT")
            print("!! active - check gateway_enforcer printed 'Installed 8 rule(s)' twice.")


# --------------------------------------------------------------------------
# COMPARE -> accuracy numbers for the report
# --------------------------------------------------------------------------
def compare(base_path, enf_path):
    base = {r["id"]: r for r in json.load(open(base_path))["results"]}
    enf = {r["id"]: r for r in json.load(open(enf_path))["results"]}

    rows, excluded = [], []
    tp = tn = fp = fn = 0          # counted per TRIAL
    for tid, b in base.items():
        e = enf.get(tid)
        if e is None:
            continue
        # A test only counts if it got through when there was no MUD.
        if b["result"] != "REACHED":
            excluded.append((tid, b["host"], b["port"], "baseline " + b["result"]))
            continue
        n = e.get("valid_trials", len(e["trials"]))
        if n == 0:
            excluded.append((tid, e["host"], e["port"], "enforced " + e["result"]))
            continue
        reached = e["reached_trials"]
        blocked = n - reached
        if e["expected"] == "BLOCK":
            tp += blocked          # attack correctly blocked
            fn += reached          # attack leaked through
            ok = e["result"] == "BLOCKED"
        else:
            tn += reached          # legit traffic correctly allowed
            fp += blocked          # legit traffic wrongly blocked
            ok = e["result"] == "REACHED"
        rows.append((e, b, ok))

    total = tp + tn + fp + fn
    print("\n=== MUD enforcement accuracy (baseline vs enforced) ===\n")
    print(f"{'ID':4} {'GROUP':9} {'PROTO':5} {'DEST':24} {'PORT':>5}  {'EXPECT':6} "
          f"{'BASELINE':8} {'ENFORCED':8} OK")
    for e, b, ok in rows:
        print(f"{e['id']:4} {e['group']:9} {e['proto']:5} {e['host'][:24]:24} {e['port']:>5}  "
              f"{e['expected']:6} {b['result']:8} {e['result']:8} {'yes' if ok else 'NO  <--'}")

    if excluded:
        print("\nExcluded (no valid evidence - unreachable without MUD, or all trials off-path):")
        for tid, host, port, res in excluded:
            print(f"  {tid} {host}:{port} -> {res}")
    off = sum(enf[r]["offpath_trials"] for r in enf if "offpath_trials" in enf[r])
    if off:
        print(f"\n!! {off} enforced-run trial(s) were OFF-PATH and ignored.")

    def pct(a, b):
        return f"{100 * a / b:.1f}%" if b else "n/a"

    print("\n--- Trial-level confusion matrix ---")
    print(f"  Attack blocked      (TP): {tp}")
    print(f"  Attack leaked       (FN): {fn}")
    print(f"  Legit allowed       (TN): {tn}")
    print(f"  Legit wrongly cut   (FP): {fp}")
    print("\n--- Metrics ---")
    print(f"  Enforcement accuracy   (TP+TN)/all : {pct(tp + tn, total)}  ({tp + tn}/{total} trials)")
    print(f"  Attack blocking rate   TP/(TP+FN)  : {pct(tp, tp + fn)}")
    print(f"  Legit pass rate        TN/(TN+FP)  : {pct(tn, tn + fp)}")
    print(f"  Tests counted / excluded           : {len(rows)} / {len(excluded)}")

    # latency of allowed traffic with vs without MUD
    lat = [(b["median_ms"], e["median_ms"]) for e, b, _ in rows
           if e["expected"] == "PASS" and b["median_ms"] and e["median_ms"]]
    if lat:
        mb = statistics.median(x for x, _ in lat)
        me = statistics.median(y for _, y in lat)
        print(f"  Allowed-flow latency  baseline {mb:.1f} ms -> enforced {me:.1f} ms "
              f"(difference {me - mb:+.1f} ms)")

    with open("accuracy_report.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "group", "proto", "host", "port", "expected",
                    "baseline", "enforced", "correct"])
        for e, b, ok in rows:
            w.writerow([e["id"], e["group"], e["proto"], e["host"], e["port"],
                        e["expected"], b["result"], e["result"], ok])
        w.writerow([])
        w.writerow(["TP", tp, "FN", fn, "TN", tn, "FP", fp])
        w.writerow(["accuracy_%", round(100 * (tp + tn) / total, 2) if total else ""])
    print("\nSaved accuracy_report.csv")


def main():
    ap = argparse.ArgumentParser(description="MUD gateway enforcement accuracy test")
    ap.add_argument("--label", help="name of this run, e.g. baseline or enforced")
    ap.add_argument("--compare", nargs=2, metavar=("BASELINE_JSON", "ENFORCED_JSON"))
    a = ap.parse_args()
    if a.compare:
        compare(*a.compare)
    elif a.label:
        run(a.label)
    else:
        ap.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
