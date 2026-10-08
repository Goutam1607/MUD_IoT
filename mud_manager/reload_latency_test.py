#!/usr/bin/env python3
"""
reload_latency_test.py - measures MUD policy hot-reload latency (Gap 5.4 / 5.6)

Runs ON THE PI while watchdog_monitor.py is running for the same device.

Each trial simulates "the manufacturer publishes a new MUD file":
  - ADD trial    : inserts a test ACE (allow TCP 9999 to 192.0.2.1)
  - REMOVE trial : takes it out again
  t0 = the moment the new file is written to the MUD server folder.
Then it polls the KERNEL (iptables -C) every 10 ms until the change is live:
  t1 = moment the rule appears / disappears in the kernel.

  end-to-end latency  = t1 - t0          (what the report quotes)
  detection delay     = watchdog noticed - t0   (depends on --interval)
  apply time          = kernel updated - watchdog noticed

192.0.2.1 is TEST-NET-1 (RFC 5737): an address reserved for documentation,
so the temporary test rule can never open a path to a real host.

The original MUD file is restored byte-for-byte at the end (even on Ctrl+C).

Run (from mud_manager/):
  sudo ../venv/bin/python3 reload_latency_test.py --name CAM \
       --file ../mud_files/ip_camera.json --trials 10
"""

import argparse
import csv
import json
import os
import shutil
import statistics
import subprocess
import sys
import time

TEST_IP, TEST_PORT = "192.0.2.1", 9999
TEST_ACE = {
    "name": "reload-latency-test",
    "matches": {"ipv4": {"destination-ipv4-network": f"{TEST_IP}/32"},
                "tcp": {"destination-port": {"operator": "eq", "port": TEST_PORT}}},
    "actions": {"forwarding": "accept"},
}


def rule_present(chain):
    return subprocess.run(["iptables", "-C", chain, "-p", "tcp", "-d", TEST_IP,
                           "--dport", str(TEST_PORT), "-j", "ACCEPT"],
                          capture_output=True).returncode == 0


def write_atomic(path, data_bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data_bytes)
    os.replace(tmp, path)   # server never reads a half-written file


def make_version(original_bytes, with_test_rule):
    mud = json.loads(original_bytes)
    acls = mud["ietf-mud:mud"]["access-lists"]["access-list"]
    first_from = mud["ietf-mud:mud"]["from-device-policy"]["access-lists"]["access-list"][0]["name"]
    target = next(a for a in acls if a["name"] == first_from)   # before deny-all
    aces = target["aces"]["ace"]
    aces[:] = [x for x in aces if x.get("name") != TEST_ACE["name"]]
    if with_test_rule:
        aces.append(TEST_ACE)
    # change last-update so every version is a genuinely new file
    mud["ietf-mud:mud"]["last-update"] = time.strftime("%Y-%m-%dT%H:%M:%S+05:30")
    return json.dumps(mud, indent=2).encode()


def read_status(name):
    try:
        with open(f"/tmp/mud_watchdog_{name}.json") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="CAM")
    ap.add_argument("--file", default="../mud_files/ip_camera.json")
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=30.0)
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run with sudo (iptables -C needs root)")
    chain = f"MUD_{a.name}_OUT"
    if subprocess.run(["iptables", "-L", chain, "-n"], capture_output=True).returncode != 0:
        sys.exit(f"Chain {chain} does not exist - start watchdog_monitor.py first")
    if not read_status(a.name):
        sys.exit("No watchdog status file - is watchdog_monitor.py running for this device?")

    path = os.path.abspath(a.file)
    with open(path, "rb") as f:
        original = f.read()
    backup = path + ".bak"
    shutil.copy2(path, backup)
    if rule_present(chain):
        sys.exit("Test rule already present - restore the original MUD file first")

    print(f"Hot-reload latency test: {a.trials} trials on {chain}\n")
    print(f"{'#':>2}  {'CHANGE':6}  {'END-TO-END':>10}  {'DETECT':>8}  {'APPLY':>7}")
    results = []
    try:
        for i in range(1, a.trials + 1):
            add = (i % 2 == 1)                       # odd = add, even = remove
            before = read_status(a.name).get("version", 0)
            data = make_version(original, add)
            t0 = time.time()
            write_atomic(path, data)
            while rule_present(chain) != add:
                if time.time() - t0 > a.timeout:
                    raise RuntimeError(f"trial {i}: change not live after {a.timeout}s")
                time.sleep(0.01)
            t1 = time.time()
            st = read_status(a.name)
            for _ in range(50):                      # status is written just after the swap
                if st.get("version", 0) > before:
                    break
                time.sleep(0.01)
                st = read_status(a.name)
            e2e = (t1 - t0) * 1000
            detect = (st.get("detected_at", t0) - t0) * 1000
            apply_ = (st.get("applied_at", t1) - st.get("detected_at", t0)) * 1000
            results.append({"trial": i, "change": "ADD" if add else "REMOVE",
                            "end_to_end_ms": round(e2e, 1), "detect_ms": round(detect, 1),
                            "apply_ms": round(apply_, 1)})
            print(f"{i:>2}  {'ADD' if add else 'REMOVE':6}  {e2e:>8.1f}ms  "
                  f"{detect:>6.1f}ms  {apply_:>5.1f}ms")
            time.sleep(1.0)
    finally:
        write_atomic(path, original)                 # restore byte-for-byte
        os.remove(backup)
        print("\nOriginal MUD file restored.")

    if not results:
        return
    e2e = [r["end_to_end_ms"] for r in results]
    app = [r["apply_ms"] for r in results]
    print("\n--- Hot-reload latency ---")
    print(f"  End-to-end  min {min(e2e):.1f} | median {statistics.median(e2e):.1f} | "
          f"max {max(e2e):.1f} ms")
    print(f"  Apply only  min {min(app):.1f} | median {statistics.median(app):.1f} | "
          f"max {max(app):.1f} ms")
    print("  (detection delay is bounded by the watchdog --interval)")

    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "tests", "reload_latency_results.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print(f"Saved {out}")


if __name__ == "__main__":
    main()
