# MUD IoT Project

A Python simulation of the **IETF MUD (Manufacturer Usage Description)** framework — RFC 8520 — applied to IoT devices.

## 📁 Project Structure

```
mud_iot_project/
|-- mud_files/              # MUD JSON files (one per device type)
|   |-- temperature_sensor.json
|   |-- smart_bulb.json
|-- mud_manager/            # MUD Manager simulation
|   |-- mud_manager.py      # Main MUD Manager (fetches, parses, enforces MUD policy)
|   |-- acl_enforcer.py     # Parses & enforces ACL rules from MUD files
|   |-- mud_validator.py    # Validates MUD file structure (RFC 8520)
|-- iot_device/             # IoT device simulation
|   |-- device_simulator.py # Simulates a device announcing its MUD URL + publishing data
|   |-- mqtt_publisher.py   # Publishes sensor data via MQTT
|-- mud_file_server/        # HTTP server hosting MUD files
|   |-- server.py           # Flask web server
|-- tests/                  # Test scripts
|   |-- test_mud_flow.py    # Full MUD flow test suite
|-- requirements.txt
|-- README.md
```

## 🚀 Step 5 — How to Run the Complete Demo

Open **three terminal windows** and run the following commands. This sequence is what you will demonstrate to the panel.

---

### Terminal 1 — Start the MUD File Server

```bash
cd mud_iot_project/mud_file_server
python server.py
# You should see: "MUD FILE SERVER Starting on http://localhost:5000"
```

---

### Terminal 2 — Start the MUD Manager

```bash
cd mud_iot_project/mud_manager
python mud_manager.py
# This will fetch the MUD file, parse rules, and show what is blocked/allowed
```

---

### Terminal 3 — Start the MQTT Broker + Device Simulator

```bash
# First start Mosquitto broker:
sudo service mosquitto start

# Then run the device simulator:
cd mud_iot_project/iot_device
python device_simulator.py
# Device will publish temperature readings every 3 seconds
```

> **Windows users:** Install Mosquitto with `winget install Mosquitto`, then start it with `net start mosquitto`

---

## 🧪 12. Testing and Validating Your Implementation

### Basic Validation Tests

**Test 1 — MUD File is Served Correctly:**
Open your browser and go to `http://localhost:5000/mud/temperature_sensor.json`.
You should see the JSON content of your MUD file. If you see JSON, the server is working.

**Test 2 — MUD Manager Fetches Successfully:**
When you run `mud_manager.py`, you should see green text saying `Successfully fetched MUD file!`
If you see red error text, check that the server (Terminal 1) is still running.

**Test 3 — Run the Automated Test Suite:**
```bash
cd mud_iot_project
python -m pytest tests/ -v
```

---

## 🔑 Key Concepts

| Concept | Description |
|---|---|
| **MUD URL** | Embedded in device firmware; announced via DHCP Option 161 |
| **MUD File** | JSON file hosted by manufacturer; describes allowed traffic |
| **MUD Manager** | Network component that fetches MUD files and programs the firewall |
| **ACL** | Access Control List generated from the MUD file rules |
| **RFC 8520** | IETF standard defining the MUD framework |

## 📡 MUD Flow (Simplified)

```
IoT Device → (DHCP Option 161: MUD URL) → Network Gateway
Network Gateway → (HTTP GET MUD URL) → MUD File Server
MUD File Server → (MUD JSON) → Network Gateway
Network Gateway → (ACL Rules) → Firewall / ACL Enforcer
```

## 📦 Install Dependencies

```bash
pip install -r requirements.txt
```

Dependencies: `flask`, `requests`, `paho-mqtt`, `colorama`
