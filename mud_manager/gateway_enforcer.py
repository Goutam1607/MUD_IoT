#!/usr/bin/env python3
"""
gateway_enforcer.py - MUD enforcement for devices BEHIND the Pi gateway.

The Pi is the WiFi gateway (wlan0 = AP "MUD_Gateway", wlan1 = uplink).
A device such as the IP camera does not run on the Pi, so its packets only
pass THROUGH the Pi. In Linux those packets cross the iptables FORWARD
chain, not INPUT/OUTPUT. This script:

  1. Fetches the device's MUD file from the MUD server and verifies the
     RSA-2048 PSS SHA-256 signature (same scheme as mud_manager.py).
  2. Parses it (accepts RFC 8519 key names AND the older short names,
     supports TCP + UDP, destination networks and DNS names, and keeps
     from-device / to-device direction).
  3. Builds two per-device chains hooked into FORWARD:
        MUD_<NAME>_OUT  (traffic FROM the device)
        MUD_<NAME>_IN   (traffic TO the device)
     each ending in LOG + DROP (default deny).
  4. Optionally keeps re-resolving DNS names (--watch) because cloud
     load-balancer IPs rotate.

Run (from mud_manager/):
  sudo ../venv/bin/python3 gateway_enforcer.py --name CAM --ip 10.42.0.17 \
       --url http://10.42.0.1:5000/mud/ip_camera.json
Remove everything it installed:
  sudo ../venv/bin/python3 gateway_enforcer.py --name CAM --ip 10.42.0.17 --remove
"""

import argparse
import os
import socket
import subprocess
import sys
import time

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_KEY_PATH = os.path.join(PROJECT_ROOT, "mud_public_key.pem")
LOG_PREFIX_LIMIT = 28  # iptables LOG prefix max length is 29 chars


# ---------------------------------------------------------------- helpers
def ipt(*args, check=False):
    """Run one iptables command. Returns True on success."""
    result = subprocess.run(["iptables", *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"[GATEWAY] iptables {' '.join(args)} FAILED: {result.stderr.strip()}")
    return result.returncode == 0


def ms_since(t0):
    return (time.perf_counter() - t0) * 1000


# ------------------------------------------------- 1. fetch + verify MUD
def fetch_and_verify(url):
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    response = requests.get(url, timeout=10)
    response.raise_for_status()
    raw = response.content
    sig_hex = response.headers.get("X-MUD-Signature")
    if not sig_hex:
        sys.exit("[GATEWAY] REJECTED: server sent no X-MUD-Signature header")
    try:
        public_key.verify(
            bytes.fromhex(sig_hex),
            raw,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError):
        sys.exit("[GATEWAY] REJECTED: MUD file signature is INVALID - no rules installed")
    print("[GATEWAY] Signature verified (RSA-2048, PSS, SHA-256)")
    return response.json()


# ------------------------------------------------------------ 2. parse
def _port(block):
    """Read a destination port from a tcp/udp match block (RFC or short keys)."""
    p = block.get("destination-port") or block.get("dst-port") or {}
    return p.get("port") if isinstance(p, dict) else None


def parse_mud(mud_file):
    mud = mud_file.get("ietf-mud:mud", {})
    acl_by_name = {a.get("name"): a
                   for a in mud.get("access-lists", {}).get("access-list", [])}

    rules = []
    for direction, key in (("from", "from-device-policy"), ("to", "to-device-policy")):
        names = [x.get("name") for x in
                 mud.get(key, {}).get("access-lists", {}).get("access-list", [])]
        for acl_name in names:
            acl = acl_by_name.get(acl_name)
            if acl is None:
                print(f"[GATEWAY] WARNING: policy lists ACL '{acl_name}' but it is not defined")
                continue
            for ace in acl.get("aces", {}).get("ace", []):
                m = ace.get("matches", {})
                ipv4 = m.get("ipv4", {})
                if "tcp" in m:
                    proto, port = "tcp", _port(m["tcp"])
                elif "udp" in m:
                    proto, port = "udp", _port(m["udp"])
                else:
                    proto, port = "any", None
                rules.append({
                    "acl": acl_name,
                    "name": ace.get("name", "unnamed"),
                    "direction": direction,
                    "proto": proto,
                    "port": port,
                    "network": ipv4.get("destination-ipv4-network") or ipv4.get("dst-address"),
                    "dnsname": ipv4.get("ietf-acldns:dst-dnsname") or ipv4.get("dst-dnsname"),
                    "action": ace.get("actions", {}).get("forwarding", "drop"),
                })
    return rules


def resolve(name, tries=3):
    """Resolve a DNS name to its IPv4 addresses (several tries: ELBs rotate)."""
    ips = set()
    for _ in range(tries):
        try:
            for info in socket.getaddrinfo(name, None, socket.AF_INET):
                ips.add(info[4][0])
        except socket.gaierror:
            pass
        time.sleep(0.2)
    return ips


# ------------------------------------------------------------ 3. install
def chain_names(name):
    return f"MUD_{name}_OUT", f"MUD_{name}_IN"


def remove(name, dev_ip):
    out_c, in_c = chain_names(name)
    while ipt("-D", "FORWARD", "-s", dev_ip, "-j", out_c):
        pass
    while ipt("-D", "FORWARD", "-d", dev_ip, "-j", in_c):
        pass
    for c in (out_c, in_c):
        ipt("-F", c)
        ipt("-X", c)
    print(f"[GATEWAY] Removed chains {out_c}, {in_c} and their FORWARD hooks")


def install(name, dev_ip, rules, dns_cache):
    out_c, in_c = chain_names(name)
    for c in (out_c, in_c):
        ipt("-N", c)          # create (fails harmlessly if it exists)
        ipt("-F", c, check=True)
        # replies to connections this policy already allowed
        ipt("-A", c, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT", check=True)

    count = 0
    for r in rules:
        chain = out_c if r["direction"] == "from" else in_c
        base = []
        if r["proto"] != "any":
            base += ["-p", r["proto"]]
            if r["port"] is not None:
                base += ["--dport", str(r["port"])]

        # destination(s): direction "from" = remote end is the destination;
        # direction "to" = remote end is the source of the packet
        addr_flag = "-d" if r["direction"] == "from" else "-s"
        if r["dnsname"]:
            ips = sorted(dns_cache.get(r["dnsname"], set()))
            if not ips:
                print(f"[GATEWAY] WARNING: {r['dnsname']} did not resolve - rule '{r['name']}' skipped")
                continue
            targets = [[addr_flag, ip] for ip in ips]
        elif r["network"] and r["network"] not in ("0.0.0.0/0", "any"):
            targets = [[addr_flag, r["network"]]]
        else:
            targets = [[]]

        for t in targets:
            if r["action"] == "accept":
                ipt("-A", chain, *base, *t, "-j", "ACCEPT", check=True)
            else:
                prefix = f"MUD_{name}_{r['direction'].upper()}_DROP: "[:LOG_PREFIX_LIMIT]
                ipt("-A", chain, *base, *t, "-m", "limit", "--limit", "10/min",
                    "-j", "LOG", "--log-prefix", prefix, check=True)
                ipt("-A", chain, *base, *t, "-j", "DROP", check=True)
            count += 1

    # final safety net: default deny even if the MUD file forgot it
    for c, d in ((out_c, "OUT"), (in_c, "IN")):
        ipt("-A", c, "-j", "DROP", check=True)

    # hook the chains into FORWARD (insert at top, only once)
    if not ipt("-C", "FORWARD", "-s", dev_ip, "-j", out_c):
        ipt("-I", "FORWARD", "1", "-s", dev_ip, "-j", out_c, check=True)
    if not ipt("-C", "FORWARD", "-d", dev_ip, "-j", in_c):
        ipt("-I", "FORWARD", "1", "-d", dev_ip, "-j", in_c, check=True)

    # drop old connections so EVERY flow is re-checked against the new policy
    subprocess.run(["conntrack", "-D", "-s", dev_ip], capture_output=True)
    subprocess.run(["conntrack", "-D", "-d", dev_ip], capture_output=True)
    return count


def print_rules(rules, dns_cache):
    print("\n[GATEWAY] === RULES FROM MUD FILE ===")
    print(f"{'DIR':<5}{'ACTION':<8}{'PROTO':<6}{'PORT':<6}DESTINATION")
    for r in rules:
        if r["dnsname"]:
            dest = f"{r['dnsname']} -> {', '.join(sorted(dns_cache.get(r['dnsname'], []))) or 'UNRESOLVED'}"
        else:
            dest = r["network"] or "any"
        print(f"{r['direction']:<5}{r['action'].upper():<8}{r['proto']:<6}"
              f"{str(r['port'] or 'any'):<6}{dest}")


# --------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="MUD enforcement on the FORWARD chain")
    ap.add_argument("--name", required=True, help="short device tag, e.g. CAM")
    ap.add_argument("--ip", required=True, help="device IP on MUD_Gateway, e.g. 10.42.0.17")
    ap.add_argument("--url", help="MUD file URL on the MUD server")
    ap.add_argument("--watch", type=int, default=0,
                    help="re-resolve DNS names every N seconds (0 = install once and exit)")
    ap.add_argument("--remove", action="store_true", help="remove this device's rules")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[GATEWAY] Run with sudo (iptables needs root)")
    if args.remove:
        remove(args.name, args.ip)
        return
    if not args.url:
        sys.exit("[GATEWAY] --url is required unless --remove")

    t0 = time.perf_counter()
    mud_file = fetch_and_verify(args.url)
    t_fetch = ms_since(t0)

    t0 = time.perf_counter()
    rules = parse_mud(mud_file)
    t_parse = ms_since(t0)

    t0 = time.perf_counter()
    names = {r["dnsname"] for r in rules if r["dnsname"]}
    dns_cache = {n: resolve(n) for n in names}
    t_dns = ms_since(t0)

    print_rules(rules, dns_cache)

    t0 = time.perf_counter()
    n = install(args.name, args.ip, rules, dns_cache)
    t_install = ms_since(t0)

    print(f"\n[GATEWAY] Installed {n} rule(s) for {args.name} ({args.ip}) on FORWARD")
    print(f"[GATEWAY] Timing: fetch+verify {t_fetch:.1f} ms | parse {t_parse:.2f} ms | "
          f"DNS {t_dns:.1f} ms | install {t_install:.1f} ms")

    if args.watch <= 0:
        return
    print(f"[GATEWAY] Watching DNS every {args.watch}s (Ctrl+C to stop; rules stay installed)")
    try:
        while True:
            time.sleep(args.watch)
            changed = False
            for name_ in names:
                new = resolve(name_) - dns_cache[name_]
                if new:
                    print(f"[GATEWAY] {name_}: new IP(s) {', '.join(sorted(new))}")
                    dns_cache[name_] |= new
                    changed = True
            if changed:
                t0 = time.perf_counter()
                install(args.name, args.ip, rules, dns_cache)
                print(f"[GATEWAY] Policy re-installed in {ms_since(t0):.1f} ms")
    except KeyboardInterrupt:
        print("\n[GATEWAY] Stopped watching. Rules remain active (use --remove to clear).")


if __name__ == "__main__":
    main()
