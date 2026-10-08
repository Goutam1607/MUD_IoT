#!/usr/bin/env python3
"""
watchdog_monitor.py - dynamic MUD policy updates for the gateway (Gap 5.4)

gateway_enforcer.py installs a device's MUD policy ONCE. If the manufacturer
publishes a new MUD file later, nothing changes until someone re-runs it.
This script keeps watching the MUD URL and hot-reloads the policy:

  every --interval seconds:
     1. GET the MUD file
     2. same bytes as last time (SHA-256)?      -> nothing to do
     3. changed -> verify RSA-2048/PSS signature
          - signature BAD  -> REJECT, keep the old (last good) rules
     4. parse -> resolve any NEW DNS names (cached names are reused)
     5. swap the rules ATOMICALLY (one iptables-restore transaction)
     6. flush conntrack for the device so every flow is re-checked
     7. log the reload (CSV) and write a status file

Why atomic (step 5)?
  gateway_enforcer.py flushes the chain and then adds rules one by one.
  For ~0.2-0.7 s the chain is half-built; because FORWARD's default policy
  is ACCEPT, a packet arriving in that gap could slip through (fail-open).
  Here the whole new chain is handed to the kernel in ONE transaction:
  packets see either the complete old policy or the complete new one.

Run (from mud_manager/, MUD server running):
  sudo ../venv/bin/python3 watchdog_monitor.py --name CAM --ip 10.42.0.17 \
       --url http://127.0.0.1:5000/mud/ip_camera.json --interval 2
Stop with Ctrl+C (rules stay installed; remove with gateway_enforcer.py --remove).
"""

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# reuse the parser / DNS / naming code from the one-shot enforcer
from gateway_enforcer import (LOG_PREFIX_LIMIT, PUBLIC_KEY_PATH, PROJECT_ROOT,
                              chain_names, ipt, parse_mud, print_rules, resolve)

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
RELOAD_LOG = os.path.join(LOG_DIR, "policy_reload_log.csv")


def now_ms():
    return time.perf_counter() * 1000


def status_path(name):
    return f"/tmp/mud_watchdog_{name}.json"


# ------------------------------------------------------------ fetch + verify
def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def fetch(url):
    """Return (raw_bytes, signature_hex) or raise on network/HTTP error."""
    r = requests.get(url, timeout=5)
    r.raise_for_status()
    return r.content, r.headers.get("X-MUD-Signature")


def signature_ok(public_key, raw, sig_hex):
    if not sig_hex:
        return False
    try:
        public_key.verify(bytes.fromhex(sig_hex), raw,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


# ------------------------------------------------------------ build + apply
def chain_lines(name, rules, dns_cache):
    """Build the full contents of MUD_<name>_OUT / _IN as iptables-restore lines."""
    out_c, in_c = chain_names(name)
    lines = []
    for c in (out_c, in_c):
        lines.append(f"-F {c}")
        lines.append(f"-A {c} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    count = 0
    for r in rules:
        chain = out_c if r["direction"] == "from" else in_c
        base = ""
        if r["proto"] != "any":
            base += f" -p {r['proto']}"
            if r["port"] is not None:
                base += f" --dport {r['port']}"
        flag = "-d" if r["direction"] == "from" else "-s"
        if r["dnsname"]:
            ips = sorted(dns_cache.get(r["dnsname"], set()))
            if not ips:
                print(f"[WATCHDOG] WARNING: {r['dnsname']} unresolved - rule '{r['name']}' skipped")
                continue
            targets = [f" {flag} {ip}" for ip in ips]
        elif r["network"] and r["network"] not in ("0.0.0.0/0", "any"):
            targets = [f" {flag} {r['network']}"]
        else:
            targets = [""]
        for t in targets:
            if r["action"] == "accept":
                lines.append(f"-A {chain}{base}{t} -j ACCEPT")
            else:
                prefix = f"MUD_{name}_{r['direction'].upper()}_DROP: "[:LOG_PREFIX_LIMIT]
                lines.append(f'-A {chain}{base}{t} -m limit --limit 10/min '
                             f'-j LOG --log-prefix "{prefix}"')
                lines.append(f"-A {chain}{base}{t} -j DROP")
            count += 1

    for c in (out_c, in_c):            # default deny safety net
        lines.append(f"-A {c} -j DROP")
    return lines, count


def apply_atomic(name, dev_ip, rules, dns_cache):
    out_c, in_c = chain_names(name)
    for c in (out_c, in_c):            # make sure the chains exist
        ipt("-N", c)
    lines, count = chain_lines(name, rules, dns_cache)
    text = "*filter\n" + "\n".join(lines) + "\nCOMMIT\n"
    res = subprocess.run(["iptables-restore", "--noflush"], input=text,
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"iptables-restore failed: {res.stderr.strip()}")

    # hook into FORWARD once (insert at top)
    if not ipt("-C", "FORWARD", "-s", dev_ip, "-j", out_c):
        ipt("-I", "FORWARD", "1", "-s", dev_ip, "-j", out_c, check=True)
    if not ipt("-C", "FORWARD", "-d", dev_ip, "-j", in_c):
        ipt("-I", "FORWARD", "1", "-d", dev_ip, "-j", in_c, check=True)

    # every existing flow must be re-checked against the NEW policy
    subprocess.run(["conntrack", "-D", "-s", dev_ip], capture_output=True)
    subprocess.run(["conntrack", "-D", "-d", dev_ip], capture_output=True)
    return count


# ------------------------------------------------------------ logging
def log_reload(row):
    os.makedirs(LOG_DIR, exist_ok=True)
    new = not os.path.isfile(RELOAD_LOG)
    with open(RELOAD_LOG, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        if new:
            w.writeheader()
        w.writerow(row)


def write_status(name, data):
    tmp = status_path(name) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, status_path(name))   # atomic: readers never see half a file


# ------------------------------------------------------------ main loop
def main():
    ap = argparse.ArgumentParser(description="Hot-reload MUD policies on the gateway")
    ap.add_argument("--name", required=True, help="device tag, e.g. CAM")
    ap.add_argument("--ip", required=True, help="device IP, e.g. 10.42.0.17")
    ap.add_argument("--url", required=True, help="MUD file URL")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="seconds between checks of the MUD URL (default 2)")
    ap.add_argument("--dns-refresh", type=float, default=300.0,
                    help="seconds between DNS re-resolution of dnsnames (default 300)")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[WATCHDOG] Run with sudo (iptables needs root)")

    pub = load_public_key()
    last_hash = None
    rules, dns_cache = [], {}
    last_dns = time.time()
    version = 0
    print(f"[WATCHDOG] Watching {a.url} every {a.interval}s for {a.name} ({a.ip}). Ctrl+C to stop.")

    try:
        while True:
            t_start = now_ms()
            detected_at = time.time()
            try:
                raw, sig = fetch(a.url)
            except requests.RequestException as e:
                print(f"[WATCHDOG] {datetime.now():%H:%M:%S} fetch failed ({e.__class__.__name__}) "
                      "- keeping current rules")
                time.sleep(a.interval)
                continue
            t_fetch = now_ms() - t_start
            h = hashlib.sha256(raw).hexdigest()

            if h != last_hash:
                t0 = now_ms()
                ok = signature_ok(pub, raw, sig)
                t_verify = now_ms() - t0
                row = {"time": datetime.now().isoformat(timespec="seconds"),
                       "device": a.name, "sha256": h[:12],
                       "fetch_ms": round(t_fetch, 2), "verify_ms": round(t_verify, 2)}
                if not ok:
                    print(f"[WATCHDOG] {datetime.now():%H:%M:%S} NEW version {h[:12]} has an "
                          "INVALID signature - REJECTED, old rules kept")
                    row.update(result="REJECTED_SIGNATURE", parse_ms="", dns_ms="",
                               install_ms="", total_ms="", rules="")
                    log_reload(row)
                    last_hash = h          # don't re-log the same bad file every cycle
                else:
                    t0 = now_ms()
                    new_rules = parse_mud(json.loads(raw))
                    t_parse = now_ms() - t0

                    t0 = now_ms()
                    for n in {r["dnsname"] for r in new_rules if r["dnsname"]}:
                        if n not in dns_cache:      # only NEW names cost DNS time
                            dns_cache[n] = resolve(n)
                    t_dns = now_ms() - t0

                    t0 = now_ms()
                    count = apply_atomic(a.name, a.ip, new_rules, dns_cache)
                    t_install = now_ms() - t0
                    applied_at = time.time()
                    total = now_ms() - t_start

                    rules, last_hash = new_rules, h
                    version += 1
                    kind = "INITIAL" if version == 1 else "RELOAD"
                    print(f"\n[WATCHDOG] {datetime.now():%H:%M:%S} {kind}: version {h[:12]} "
                          f"applied, {count} rule(s)")
                    print_rules(rules, dns_cache)
                    print(f"[WATCHDOG] fetch {t_fetch:.1f} | verify {t_verify:.2f} | parse "
                          f"{t_parse:.2f} | dns {t_dns:.1f} | install {t_install:.1f} | "
                          f"total {total:.1f} ms")
                    row.update(result=kind, parse_ms=round(t_parse, 2), dns_ms=round(t_dns, 1),
                               install_ms=round(t_install, 1), total_ms=round(total, 1),
                               rules=count)
                    log_reload(row)
                    write_status(a.name, {"sha256": h, "version": version,
                                          "detected_at": detected_at,
                                          "applied_at": applied_at})

            # periodic DNS refresh: cloud load-balancer IPs rotate
            if rules and time.time() - last_dns > a.dns_refresh:
                last_dns = time.time()
                changed = False
                for n in list(dns_cache):
                    new = resolve(n) - dns_cache[n]
                    if new:
                        dns_cache[n] |= new
                        changed = True
                        print(f"[WATCHDOG] {n}: new IP(s) {', '.join(sorted(new))}")
                if changed:
                    apply_atomic(a.name, a.ip, rules, dns_cache)
                    print("[WATCHDOG] Rules re-applied with new DNS addresses")

            time.sleep(a.interval)
    except KeyboardInterrupt:
        print("\n[WATCHDOG] Stopped. Rules remain active "
              "(remove with gateway_enforcer.py --name ... --remove).")


if __name__ == "__main__":
    main()
