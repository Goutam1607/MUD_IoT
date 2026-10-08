# Hardware Bill of Materials (BOM) — MUD-based IoT Security Gateway

Prices are what the team actually paid (INR, October 2026).

## A. Gateway (the security system itself)

| # | Item | Purpose in the project | Qty | Price (₹) |
|---|------|------------------------|-----|-----------|
| 1 | Raspberry Pi 3B+ (1 GB RAM) | MUD manager, MUD file server, iptables enforcement, WiFi access point (wlan0, MUD_Gateway) | 1 | ~3,000 |
| 2 | microSD card, 16 GB | Raspberry Pi OS Lite + project code | 1 | ~400 |
| 3 | TP-Link TL-WN725N USB WiFi dongle | Internet uplink (wlan1) so the built-in WiFi can act as the AP | 1 | 439 |
| 4 | USB card reader | One-time: flashing the OS onto the microSD card | 1 | 80 |
| 5 | 5V/2A power adapter | Reused an existing phone charger (a laptop USB port caused undervoltage) | 1 | 0 (reused) |
|   | **Gateway subtotal** | | | **~3,919** |

## B. Devices under test (protected by the gateway)

| # | Item | Purpose | Qty | Price (₹) |
|---|------|---------|-----|-----------|
| 6 | CP PLUS CP-E35Q 3MP WiFi camera | Real commercial IoT device with its own MUD file (`ip_camera.json`) | 1 | 2,549 |
| 7 | DHT11 temperature/humidity sensor | MQTT sensor device (GPIO 4) | 1 | 0 (obtained free) |
|   | **Test-device subtotal** | | | **~2,549** |

## C. Software

All software is free and open source: Raspberry Pi OS, Python 3, Flask, `cryptography` (RSA-2048/PSS),
iptables / conntrack, NetworkManager, Mosquitto MQTT broker. **Software cost: ₹0.**

## Totals

| | Cost (₹) |
|---|---|
| Gateway (A) | ~3,919 |
| Test devices (B) | ~2,549 |
| **Complete prototype (A + B)** | **~6,468** |

## Cost-related observations (Gap 5.6)

- **Marginal cost per additional protected device: ₹0 in hardware.** Protecting a new IoT device
  only needs its MUD file; the same gateway enforces all devices on MUD_Gateway.
- **No enterprise infrastructure is required.** East-west (device-to-device) isolation is achieved
  with WiFi AP isolation + Private-VLAN proxy ARP on the Pi, instead of managed switches.
- Excluded from the totals: the power adapter (reused) and the laptop/phone used for testing.

## Measured performance on this hardware (for reproducibility)

| Metric | Result |
|---|---|
| Enforcement accuracy (29 tests × 3 trials, baseline-controlled) | 100% (87/87 trials) |
| Attack blocking rate | 100% (72/72) — incl. 36/36 east-west attacks |
| Legitimate traffic pass rate | 100% (15/15) |
| MUD signature verification (RSA-2048, PSS, SHA-256) | ~1.3 ms |
| Policy hot-reload, apply time (detect → enforced) | median 166 ms (156–186 ms, 10 trials) |
| Policy hot-reload, end-to-end (published → enforced, 2 s polling) | median 1.12 s |
| Boot to camera policy enforced (systemd) | ~10 s after services start |
