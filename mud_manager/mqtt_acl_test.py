#!/usr/bin/env python3
"""
mqtt_acl_test.py - topic-level enforcement accuracy test (Gap 5.3)

Runs ON THE PI (the broker is on the Pi). Plays a compromised DHT11 sensor that
uses its real MQTT login but tries things its MUD file does not allow.

  baseline : run after  `mqtt_acl_manager.py --disable`  (port-level only)
  enforced : run after  `mqtt_acl_manager.py --url ...`   (topic ACL active)

How a result is decided
  publish   : a separate MONITOR client (subscribed to "#") must actually
              receive the message within the timeout -> REACHED
  subscribe : the monitor publishes a unique message on a topic; the test
              client must receive it -> REACHED
  connect   : broker accepts the login (CONNACK rc=0) -> REACHED

Usage (from mud_manager/):
  ../venv/bin/python3 mqtt_acl_test.py --label baseline
  ../venv/bin/python3 mqtt_acl_test.py --label enforced
"""

import argparse
import csv
import json
import os
import threading
import time
import uuid
import warnings

import paho.mqtt.client as mqtt

warnings.filterwarnings("ignore", category=DeprecationWarning)  # paho 2.x VERSION1 notice

BROKER, PORT = "127.0.0.1", 1883
TIMEOUT = 2.0
TRIALS = 3
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDS_DIR = os.path.join(PROJECT_ROOT, "device_creds")

# (id, kind, description, topic, expected)
TESTS = [
    ("M01", "publish",   "sensor publishes its own reading",            "sensors/temperature",        "PASS"),
    ("M02", "subscribe", "sensor reads its own config topic",           "sensors/temperature/config", "PASS"),
    ("M03", "publish",   "spoofed command: unlock the door",            "home/door/unlock",           "BLOCK"),
    ("M04", "publish",   "inject fake data as another device",          "sensors/humidity",           "BLOCK"),
    ("M05", "publish",   "tamper with the camera's control topic",      "cameras/cam1/control",       "BLOCK"),
    ("M06", "subscribe", "spy on every topic (#)",                      "#",                          "BLOCK"),
    ("M07", "subscribe", "spy on another device's data",                "cameras/cam1/control",       "BLOCK"),
    ("M08", "connect",   "anonymous client (no username)",              None,                         "BLOCK"),
    ("M09", "connect",   "sensor username with WRONG password",         None,                         "BLOCK"),
    ("M10", "connect",   "unknown device 'rogue' with a guessed password", None,                      "BLOCK"),
]


def creds(user):
    try:
        with open(os.path.join(CREDS_DIR, f"{user}.json")) as f:
            return json.load(f)["password"]
    except OSError:
        return "not-yet-generated"      # baseline: broker ignores passwords anyway


def new_client(cid):
    try:   # paho-mqtt 2.x
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=cid)
    except AttributeError:   # paho-mqtt 1.x
        return mqtt.Client(client_id=cid)


def connect(user, password, cid=None):
    """Return (client, connack_rc). rc 0 = accepted; client is None if refused."""
    c = new_client(cid or f"test-{uuid.uuid4().hex[:8]}")
    if user is not None:
        c.username_pw_set(user, password)
    ev, box = threading.Event(), {}

    def on_connect(cl, ud, flags, rc):
        box["rc"] = rc
        ev.set()
    c.on_connect = on_connect
    try:
        c.connect(BROKER, PORT, keepalive=30)
    except OSError as e:
        return None, f"socket error {e}"
    c.loop_start()
    ev.wait(TIMEOUT)
    rc = box.get("rc", "timeout")
    if rc != 0:
        c.loop_stop()
        c.disconnect()
        return None, rc
    return c, 0


def wait_for(client, topic_filter_sub, publish_fn, marker):
    """Subscribe `client`, run publish_fn(), report whether `marker` arrived."""
    got = threading.Event()

    def on_message(cl, ud, msg):
        if marker in msg.payload.decode(errors="ignore"):
            got.set()
    client.on_message = on_message
    sub_ev = threading.Event()
    client.on_subscribe = lambda *a: sub_ev.set()
    client.subscribe(topic_filter_sub, qos=1)
    sub_ev.wait(TIMEOUT)
    time.sleep(0.2)
    publish_fn()
    ok = got.wait(TIMEOUT)
    client.unsubscribe(topic_filter_sub)
    return ok


def run_trial(test, monitor, sensor_pw):
    tid, kind, _, topic, _ = test
    marker = f"mud-test-{uuid.uuid4().hex}"

    if kind == "connect":
        if tid == "M08":
            c, rc = connect(None, None)
        elif tid == "M09":
            c, rc = connect("dht11-sensor", "wrong-" + sensor_pw)
        else:
            c, rc = connect("rogue", "password123")
        if c:
            c.loop_stop(); c.disconnect()
        return "REACHED" if rc == 0 else "BLOCKED"

    sensor, rc = connect("dht11-sensor", sensor_pw)
    if sensor is None:
        return "CONN_FAIL"
    try:
        if kind == "publish":
            # monitor listens; sensor publishes
            ok = wait_for(monitor, topic, lambda: sensor.publish(topic, marker, qos=1), marker)
        else:
            # sensor listens; monitor publishes on a concrete topic
            pub_topic = "home/secret/test" if topic == "#" else topic
            ok = wait_for(sensor, topic, lambda: monitor.publish(pub_topic, marker, qos=1), marker)
        return "REACHED" if ok else "BLOCKED"
    finally:
        sensor.loop_stop()
        sensor.disconnect()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, help="baseline or enforced")
    a = ap.parse_args()

    sensor_pw = creds("dht11-sensor")
    monitor, rc = connect("mud-monitor", creds("mud-monitor"), cid="mud-monitor-test")
    if monitor is None:
        raise SystemExit(f"Monitor account could not connect (rc={rc}). "
                         "Run mqtt_acl_manager.py first, or check mosquitto is running.")

    print(f"\n=== MQTT topic-ACL test - run '{a.label}' ({TRIALS} trials each) ===\n")
    print(f"{'ID':4} {'KIND':9} {'TOPIC':28} {'EXPECT':6} {'RESULT':8} TRIALS  DESCRIPTION")
    rows, tp = [], {"TP": 0, "FN": 0, "TN": 0, "FP": 0}
    for t in TESTS:
        tid, kind, desc, topic, expected = t
        outs = [run_trial(t, monitor, sensor_pw) for _ in range(TRIALS)]
        reached = outs.count("REACHED")
        result = "REACHED" if reached > TRIALS / 2 else "BLOCKED"
        if "CONN_FAIL" in outs:
            result = "CONN_FAIL"
        for o in outs:
            if expected == "BLOCK":
                tp["TP" if o != "REACHED" else "FN"] += 1
            else:
                tp["TN" if o == "REACHED" else "FP"] += 1
        ok = (result == "BLOCKED") if expected == "BLOCK" else (result == "REACHED")
        print(f"{tid:4} {kind:9} {str(topic or '-'):28} {expected:6} {result:8} "
              f"{reached}/{TRIALS}    {desc}{'' if ok else '   <-- NO'}")
        rows.append({"id": tid, "kind": kind, "topic": topic or "", "expected": expected,
                     "result": result, "reached_trials": reached, "trials": TRIALS,
                     "correct": ok, "description": desc})

    monitor.loop_stop()
    monitor.disconnect()
    total = sum(tp.values())
    correct = tp["TP"] + tp["TN"]
    print(f"\nAttacks blocked {tp['TP']} | attacks leaked {tp['FN']} | "
          f"legit allowed {tp['TN']} | legit wrongly blocked {tp['FP']}")
    print(f"Accuracy {100 * correct / total:.1f}% ({correct}/{total} trials)")

    out = os.path.join(PROJECT_ROOT, "tests", f"mqtt_acl_{a.label}.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Saved {out}")


if __name__ == "__main__":
    main()
