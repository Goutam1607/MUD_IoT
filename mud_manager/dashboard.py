import csv
import os
import time

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'mud_traffic_log.csv')


def read_log():
    if not os.path.isfile(LOG_FILE):
        return []
    with open(LOG_FILE, newline='') as f:
        reader = csv.DictReader(f)
        return list(reader)


def print_dashboard():
    rows = read_log()
    os.system('cls' if os.name == 'nt' else 'clear')   # clears the screen each refresh
    print("=" * 80)
    print("          MUD ACCESS CONTROL — LIVE MONITORING DASHBOARD")
    print("=" * 80)

    allowed_count = sum(1 for r in rows if r["action"] == "ALLOWED")
    blocked_count = sum(1 for r in rows if r["action"] == "BLOCKED")

    print(f"Total Events Logged: {len(rows)}    |   Allowed: {allowed_count}   |   Blocked: {blocked_count}")
    print("-" * 80)
    print(f"{'Time':<20}{'Device':<22}{'Destination':<18}{'Port':<8}{'Action'}")
    print("-" * 80)

    # show only the most recent 15 events so the screen doesn't overflow
    for row in rows[-15:]:
        action_display = row['action']
        print(f"{row['timestamp']:<20}{row['device']:<22}{row['destination_ip']:<18}{row['port']:<8}{action_display}")

    print("=" * 80)
    print("Refreshing every 3 seconds... Press Ctrl+C to stop.")


if __name__ == "__main__":
    try:
        while True:
            print_dashboard()
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
