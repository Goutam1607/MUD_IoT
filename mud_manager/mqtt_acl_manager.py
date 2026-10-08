#!/usr/bin/env python3
"""
mqtt_acl_manager.py - MQTT topic-level MUD enforcement (Gap 5.3)

THE PROBLEM
  iptables only sees IP addresses and ports. "Allow TCP 1883" lets a device
  talk to the MQTT broker - but then it can publish to ANY topic (e.g. a
  hacked sensor publishing "home/door/unlock") or subscribe to "#" and spy
  on every other device. Port-level MUD cannot stop that.

THE FIX
  1. The MUD file declares an extension (RFC 8520 allows extensions):
        "extensions": ["mqtt-topic-acl"],
        "mqtt-topic-acl:policy": {
            "username": "dht11-sensor",
            "publish":   ["sensors/temperature"],
            "subscribe": ["sensors/temperature/config"] }
  2. This script fetches each MUD file, VERIFIES its RSA signature, reads the
     extension and generates:
        /etc/mosquitto/mud_acl     - per-device topic permissions
        /etc/mosquitto/mud_passwd  - per-device login (hashed)
        /etc/mosquitto/conf.d/mud_acl.conf - no anonymous clients, use the above
  3. Mosquitto (the broker) then enforces it on every PUBLISH / SUBSCRIBE.

  Device passwords are generated once and kept in device_creds/<user>.json
  (git-ignored, readable only by the pi user). Re-running keeps them.

Run (from mud_manager/, MUD server running):
  sudo ../venv/bin/python3 mqtt_acl_manager.py \
       --url http://127.0.0.1:5000/mud/temperature_sensor.json
Undo (back to port-level only):
  sudo ../venv/bin/python3 mqtt_acl_manager.py --disable
"""

import argparse
import json
import os
import pwd
import secrets
import subprocess
import sys

from gateway_enforcer import PROJECT_ROOT, fetch_and_verify

ACL_FILE = "/etc/mosquitto/mud_acl"
PASSWD_FILE = "/etc/mosquitto/mud_passwd"
CONF_FILE = "/etc/mosquitto/conf.d/mud_acl.conf"
CREDS_DIR = os.path.join(PROJECT_ROOT, "device_creds")
MONITOR_USER = "mud-monitor"     # admin/test account: may read+write everything


def owner():
    """The normal user who ran sudo (so creds files belong to pi, not root)."""
    name = os.environ.get("SUDO_USER", "pi")
    pw = pwd.getpwnam(name)
    return pw.pw_uid, pw.pw_gid


def load_or_create_creds(username):
    os.makedirs(CREDS_DIR, exist_ok=True)
    path = os.path.join(CREDS_DIR, f"{username}.json")
    if os.path.isfile(path):
        with open(path) as f:
            return json.load(f)["password"]
    password = secrets.token_urlsafe(18)
    with open(path, "w") as f:
        json.dump({"username": username, "password": password}, f)
    uid, gid = owner()
    os.chown(CREDS_DIR, uid, gid)
    os.chown(path, uid, gid)
    os.chmod(path, 0o600)
    print(f"[MQTT-ACL] New credentials for '{username}' -> {path}")
    return password


def extract_policy(mud_file):
    mud = mud_file.get("ietf-mud:mud", {})
    if "mqtt-topic-acl" not in mud.get("extensions", []):
        return None
    pol = mud.get("mqtt-topic-acl:policy", {})
    if not pol.get("username"):
        sys.exit("[MQTT-ACL] extension declared but policy has no username")
    return {"username": pol["username"],
            "client_id": pol.get("client-id"),
            "publish": pol.get("publish", []),
            "subscribe": pol.get("subscribe", [])}


def write_root_file(path, text, mode=0o600, mosquitto_owned=False):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    if mosquitto_owned:
        m = pwd.getpwnam("mosquitto")
        os.chown(tmp, m.pw_uid, m.pw_gid)
    os.replace(tmp, path)


def reload_broker():
    subprocess.run(["systemctl", "restart", "mosquitto"], check=False)
    state = subprocess.run(["systemctl", "is-active", "mosquitto"],
                           capture_output=True, text=True).stdout.strip()
    if state != "active":
        print("[MQTT-ACL] ERROR: mosquitto did not start. Last log lines:")
        subprocess.run(["journalctl", "-u", "mosquitto", "-n", "15", "--no-pager"])
        sys.exit(1)
    print("[MQTT-ACL] Mosquitto restarted and active")


def disable():
    for p in (CONF_FILE,):
        if os.path.exists(p):
            os.remove(p)
    print("[MQTT-ACL] Topic ACL disabled (port-level only, anonymous allowed)")
    # without our conf, Mosquitto 2.x needs an explicit listener for anonymous use
    write_root_file("/etc/mosquitto/conf.d/mud_open.conf",
                    "# port-level only (baseline test) - local clients only\nlistener 1883 127.0.0.1\nallow_anonymous true\n",
                    mode=0o644)
    reload_broker()


def main():
    ap = argparse.ArgumentParser(description="Generate Mosquitto topic ACLs from MUD files")
    ap.add_argument("--url", action="append", default=[],
                    help="MUD file URL (repeat for several devices)")
    ap.add_argument("--disable", action="store_true",
                    help="remove topic ACLs (baseline: port-level only)")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[MQTT-ACL] Run with sudo (writes /etc/mosquitto)")
    if a.disable:
        disable()
        return
    if not a.url:
        sys.exit("[MQTT-ACL] give at least one --url")

    acl = ["# Generated by mqtt_acl_manager.py from signed MUD files - do not edit\n"]
    users = {}

    for url in a.url:
        mud = fetch_and_verify(url)               # exits if signature is bad
        pol = extract_policy(mud)
        if pol is None:
            print(f"[MQTT-ACL] {url}: no mqtt-topic-acl extension - skipped")
            continue
        u = pol["username"]
        users[u] = load_or_create_creds(u)
        acl.append(f"\n# {url}\nuser {u}\n")
        for t in pol["publish"]:
            acl.append(f"topic write {t}\n")
        for t in pol["subscribe"]:
            acl.append(f"topic read {t}\n")
        print(f"[MQTT-ACL] {u}: publish {pol['publish']} | subscribe {pol['subscribe']}")

    # monitoring / test account
    users[MONITOR_USER] = load_or_create_creds(MONITOR_USER)
    acl.append(f"\n# monitoring + test account\nuser {MONITOR_USER}\ntopic readwrite #\n")

    write_root_file(ACL_FILE, "".join(acl), mode=0o600, mosquitto_owned=True)

    # password file: write plain user:pass, then let mosquitto_passwd hash it
    write_root_file(PASSWD_FILE, "".join(f"{u}:{p}\n" for u, p in users.items()),
                    mode=0o600, mosquitto_owned=True)
    subprocess.run(["mosquitto_passwd", "-U", PASSWD_FILE], check=True)
    m = pwd.getpwnam("mosquitto")
    os.chown(PASSWD_FILE, m.pw_uid, m.pw_gid)
    os.chmod(PASSWD_FILE, 0o600)

    if os.path.exists("/etc/mosquitto/conf.d/mud_open.conf"):
        os.remove("/etc/mosquitto/conf.d/mud_open.conf")
    write_root_file(CONF_FILE,
                    "# MUD topic-level enforcement (generated)\n"
                    "listener 1883\n"
                    "allow_anonymous false\n"
                    f"password_file {PASSWD_FILE}\n"
                    f"acl_file {ACL_FILE}\n", mode=0o644)

    print(f"[MQTT-ACL] Wrote {ACL_FILE} ({len(users)} users) and {CONF_FILE}")
    reload_broker()


if __name__ == "__main__":
    main()
