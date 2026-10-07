import re
import time
import sys
from scapy.all import ARP, Ether, srp
from mud_manager import process_device
import subprocess


def get_current_subnet(interface="wlan0"):
    """
    Asks the Pi's own OS what IP + subnet it currently has on wlan0,
    instead of relying on a hardcoded value. This makes the detector
    work correctly even if the hotspot/router reassigns a new IP range.
    Equivalent to running: ip -o -f inet addr show wlan0
    """
    result = subprocess.run(
        ["ip", "-o", "-f", "inet", "addr", "show", interface],
        capture_output=True, text=True
    )
    match = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/(\d+)", result.stdout)
    if match:
        base_ip = match.group(1)
        return f"{base_ip}.0/24"
    return None

# ============================================================
# STEP A: Simulated DHCP Option 161 registry
# In real RFC 8520, a device announces its own MUD URL during
# DHCP handshake. Since our Pi is a WiFi CLIENT (not the router
# running DHCP), we can't intercept that handshake. So we keep
# a local MAC -> MUD URL lookup table that acts as a stand-in
# for that registry. This is a documented, defensible simplification.
# ============================================================

DEVICE_REGISTRY = {
    "e2:f7:bc:5e:d6:82": "http://localhost:5000/mud/temperature_sensor.json",
    "c0:35:32:7a:e4:d3": "http://localhost:5000/mud/temperature_sensor.json",
}

SCAN_INTERVAL = 8                  # seconds between scans


def scan_network(ip_range):
    """
    Sends an ARP 'who-has' broadcast to every IP in ip_range and
    collects replies. Each reply tells us: 'I am IP x, my MAC is y'.
    This is exactly how your phone's WiFi settings page knows which
    devices are on the network -- same technique, just done manually.
    """
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=1, verbose=False, iface="wlan0", retry=0)

    devices = []
    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices


def main():
    network_range = get_current_subnet("wlan0")
    if not network_range:
        print("[DEVICE DETECTOR] ERROR: Could not detect wlan0 subnet. Exiting.")
        sys.exit(1)

    print("=" * 60)
    print("[DEVICE DETECTOR] Starting continuous ARP scan")
    print(f"[DEVICE DETECTOR] Auto-detected subnet: {network_range}")
    print(f"[DEVICE DETECTOR] Scanning every {SCAN_INTERVAL}s")
    print("=" * 60)

    known_macs = set()

    try:
        while True:
            current_devices = scan_network(network_range)
            current_macs = {d["mac"] for d in current_devices}

            new_macs = current_macs - known_macs

            for device in current_devices:
                mac = device["mac"]
                ip = device["ip"]

                if mac in new_macs:
                    print(f"\n[DEVICE DETECTOR] New device found! IP={ip} MAC={mac}")

                    if mac in DEVICE_REGISTRY:
                        mud_url = DEVICE_REGISTRY[mac]
                        print(f"[DEVICE DETECTOR] MAC recognized. Fetching MUD policy...")
                        process_device(device_name=f"Device ({mac})", mud_url=mud_url)
                    else:
                        print(f"[DEVICE DETECTOR] MAC {mac} not in registry. "
                              f"No MUD policy available -- device ignored (fail-safe default).")

            known_macs = current_macs
            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print("\n[DEVICE DETECTOR] Stopped by user (Ctrl+C).")
        sys.exit(0)


if __name__ == "__main__":
    main()
