# Hardware Bill of Materials (BOM) – MUD IoT Security Gateway

Prices are what the team actually paid (INR, 2026). Research gap addressed: **5.6 – cost-quantified reproducibility**.

## 1. MUD gateway (the security system itself)

| # | Component | Role in the system | Qty | Cost (₹) |
|---|-----------|--------------------|-----|---------:|
| 1 | Raspberry Pi 3B+ (1 GB RAM) | MUD manager, MUD file server, iptables enforcement, Wi-Fi AP `MUD_Gateway` (built-in BCM43455, wlan0) | 1 | 4,000 |
| 2 | microSD card, 16 GB | Raspberry Pi OS Lite + project code + logs | 1 | 400 |
| 3 | TP-Link TL-WN725N V3 USB Wi-Fi (RTL8188EUS) | Uplink to internet (wlan1, client mode) | 1 | 439 |
| 4 | 5 V / 2 A power adapter | Power supply (existing phone charger reused) | 1 | 0 |
| | **Gateway subtotal** | | | **4,839** |

## 2. Setup tools (one-time)

| # | Component | Role | Qty | Cost (₹) |
|---|-----------|------|-----|---------:|
| 5 | USB microSD card reader | Flashing the OS image | 1 | 80 |

## 3. Protected IoT devices (test devices, not part of the gateway)

| # | Component | Role | Qty | Cost (₹) |
|---|-----------|------|-----|---------:|
| 6 | CP Plus CP-E35Q 3 MP Wi-Fi camera | Real cloud IoT device enrolled with `ip_camera.json` | 1 | 2,549 |
| 7 | DHT11 temperature/humidity sensor | Sensor device (GPIO 4, MQTT publisher) | 1 | 0 (sourced free) |

## 4. Software

| Component | Cost (₹) |
|-----------|---------:|
| Raspberry Pi OS Lite, Python 3, Flask, `cryptography`, iptables / conntrack, NetworkManager, Mosquitto | 0 (open source) |

## 5. Totals

| Scope | Cost (₹) |
|-------|---------:|
| **MUD gateway (reproduce the security system)** | **4,839** |
| Gateway + setup tools | 4,919 |
| Complete test bench (gateway + tools + camera + sensor) | 7,468 |

**Marginal cost of protecting one more IoT device: ₹0 on the gateway side** – only a new MUD file is needed; no extra hardware.

## 6. Measured performance on this hardware (for context)

| Metric | Result |
|--------|--------|
| Enforcement accuracy (29 tests × 3 trials, baseline-controlled) | 100 % (87/87) |
| Attack blocking rate | 100 % (72/72), incl. 36/36 same-Wi-Fi (east-west) attacks |
| Legitimate camera traffic allowed | 100 % (15/15); live view works under enforcement |
| MUD signature verification (RSA-2048, PSS, SHA-256) | ~1.3–1.5 ms |
| Policy hot-reload, apply (verify + parse + atomic install) | median 166 ms (156–186 ms, 10 trials) |
| Policy hot-reload, end-to-end (publish → enforced) | median 1.12 s, bounded by 2 s polling interval |
| Boot → camera protected (systemd) | ~10 s after services start |

## 7. What this setup does NOT need

- No managed/enterprise switch or VLAN configuration: east-west isolation is done with Wi-Fi AP isolation + Linux private-VLAN proxy ARP on the Pi.
- No commercial MUD manager or NAC appliance.
- No Ethernet cabling: the gateway is entirely Wi-Fi (AP on wlan0, uplink on wlan1).
