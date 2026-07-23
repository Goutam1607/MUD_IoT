import requests
import json
import csv
import os
from rule_enforcer import apply_all_rules
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'mud_traffic_log.csv')


def log_decision(src_device, dst_ip, port, action, matched_rule):
    """
    Appends one row to a CSV log file every time a decision is made.
    CSV (Comma-Separated Values) is used because it opens directly in
    Excel, which makes it easy to show your panel a clean results table.
    """
    file_exists = os.path.isfile(LOG_FILE)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        # Write the header row only the very first time the file is created
        if not file_exists:
            writer.writerow(["timestamp", "device", "destination_ip", "port", "action", "matched_rule"])
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_device,
            dst_ip,
            port,
            action,
            matched_rule
        ])


def fetch_mud_file(mud_url):
    """Step 1: Fetch the MUD file from the manufacturer's server"""
    print(f"\n{Fore.CYAN}[MUD MANAGER] Fetching MUD file from: {mud_url}")
    try:
        response = requests.get(mud_url, timeout=10)
        response.raise_for_status()
        mud_file = response.json()
        print(f"{Fore.GREEN}[MUD MANAGER] Successfully fetched MUD file!")
        return mud_file
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[MUD MANAGER] ERROR: Could not fetch MUD file: {e}")
        return None


def parse_mud_rules(mud_file):
    """Step 2: Parse and display the rules from the MUD file"""
    print(f"\n{Fore.YELLOW}[MUD MANAGER] Parsing MUD file rules...")

    mud_info = mud_file.get("ietf-mud:mud", {})
    print(f"  Device Info: {mud_info.get('systeminfo', 'Unknown')}")
    print(f"  MUD URL:     {mud_info.get('mud-url', 'Unknown')}")
    print(f"  Last Update: {mud_info.get('last-update', 'Unknown')}")

    acls = mud_file.get("ietf-mud:mud", {}).get("access-lists", {})
    acl_list = acls.get("access-list", [])

    rules = []
    for acl in acl_list:
        aces = acl.get("aces", {}).get("ace", [])
        for ace in aces:
            name   = ace.get("name", "unknown")
            action = ace.get("actions", {}).get("forwarding", "unknown")
            matches = ace.get("matches", {})
            dst    = matches.get("ipv4", {}).get("dst-address", "any")
            tcp    = matches.get("tcp", {}).get("dst-port", {})
            port   = tcp.get("port", "any")
            rules.append({"name": name, "action": action, "dst": dst, "port": port})
    return rules


def simulate_acl_enforcement(rules, test_connections, device_name="Temperature Sensor v2"):
    """Step 3: Simulate enforcing the ACL rules"""
    print(f"\n{Fore.MAGENTA}[MUD MANAGER] === RULES TRANSLATED FROM MUD FILE ===")
    print(f"{'Rule Name':<25} {'Destination':<20} {'Port':<8} {'Action'}")
    print("-" * 65)
    for rule in rules:
        color = Fore.GREEN if rule["action"] == "accept" else Fore.RED
        print(f"{color}{rule['name']:<25} {str(rule['dst']):<20} {str(rule['port']):<8} {rule['action'].upper()}")

    print(f"\n{Fore.MAGENTA}[MUD MANAGER] === TESTING SAMPLE CONNECTIONS ===")
    for conn in test_connections:
        allowed    = check_connection(rules, conn["dst"], conn["port"])
        status_text = "ALLOWED" if allowed else "BLOCKED"
        color       = Fore.GREEN if allowed else Fore.RED
        print(f"  {conn['desc']:<35} {conn['dst']}:{conn['port']} -> {color}{status_text}")

        # NEW: write this decision permanently to the log file
        log_decision(
            src_device=device_name,
            dst_ip=conn["dst"],
            port=conn["port"],
            action=status_text,
            matched_rule=conn["desc"]
        )

    print(f"\n{Fore.CYAN}[MUD MANAGER] All decisions logged to: {LOG_FILE}")


def check_connection(rules, dst_ip, port):
    for rule in rules:
        if rule["action"] == "drop":
            return False
        if str(rule["port"]) == str(port):
            return True
    return False


def process_device(device_name, mud_url):
    print(f"\n{'=' * 60}")
    print(f"{Fore.CYAN}NEW DEVICE CONNECTED: {device_name}")
    print(f"MUD URL: {mud_url}")
    print(f"{'=' * 60}")

    mud_file = fetch_mud_file(mud_url)
    if not mud_file:
        return

    rules = parse_mud_rules(mud_file)
    apply_all_rules(rules)  # NEW: push these rules to the real Linux firewall

    # Test cases: what traffic should be allowed vs blocked?
    test_connections = [
            {"dst": "10.211.83.196", "port": 1883, "desc": "MQTT to Pi broker (ALLOWED by MUD)"},
            {"dst": "8.8.8.8",       "port": 443,  "desc": "HTTPS firmware update (ALLOWED by MUD)"},
            {"dst": "10.211.83.201", "port": 80,   "desc": "HTTP to phone gateway (BLOCKED by MUD)"},
            {"dst": "10.211.83.201", "port": 22,   "desc": "SSH attack to gateway (BLOCKED by MUD)"},
    ]
    simulate_acl_enforcement(rules, test_connections, device_name=device_name)


if __name__ == "__main__":
    print(f"{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.CYAN}[MUD MANAGER] MUD MANAGER - RFC 8520 Demonstration")
    print(f"{Fore.CYAN}{'=' * 60}")
    process_device(
        device_name="Temperature Sensor v2",
        mud_url="http://localhost:5000/mud/temperature_sensor.json"
    )
