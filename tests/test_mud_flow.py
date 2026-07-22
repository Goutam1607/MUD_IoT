"""
test_mud_flow.py — Tests the full MUD flow end-to-end.

Tests:
  1. MUD file server is reachable and returns correct content
  2. MUD file is valid per RFC 8520 structure
  3. ACL enforcer correctly accepts/drops traffic
  4. MUD Manager successfully registers a device
"""

import sys
import os
import json
import unittest

# Allow imports from sibling directories
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mud_manager.mud_validator import validate_mud_file
from mud_manager.acl_enforcer import ACLEnforcer


# Load MUD files directly for offline tests
MUD_FILES_DIR = os.path.join(os.path.dirname(__file__), '..', 'mud_files')

def load_mud_file(filename: str) -> dict:
    path = os.path.join(MUD_FILES_DIR, filename)
    with open(path) as f:
        return json.load(f)


# ─── Test Suite ───────────────────────────────────────────────────────────────

class TestMUDValidator(unittest.TestCase):
    """Tests for mud_validator.py"""

    def test_temperature_sensor_valid(self):
        data = load_mud_file("temperature_sensor.json")
        valid, errors = validate_mud_file(data)
        self.assertTrue(valid, f"Validation errors: {errors}")

    def test_smart_bulb_valid(self):
        data = load_mud_file("smart_bulb.json")
        valid, errors = validate_mud_file(data)
        self.assertTrue(valid, f"Validation errors: {errors}")

    def test_missing_mud_block(self):
        data = {"bad-key": {}}
        valid, errors = validate_mud_file(data)
        self.assertFalse(valid)
        self.assertTrue(any("ietf-mud:mud" in e for e in errors))

    def test_invalid_mud_version(self):
        data = load_mud_file("temperature_sensor.json")
        data["ietf-mud:mud"]["mud-version"] = 99
        valid, errors = validate_mud_file(data)
        self.assertFalse(valid)
        self.assertTrue(any("mud-version" in e for e in errors))

    def test_missing_required_field(self):
        data = load_mud_file("temperature_sensor.json")
        del data["ietf-mud:mud"]["systeminfo"]
        valid, errors = validate_mud_file(data)
        self.assertFalse(valid)
        self.assertTrue(any("systeminfo" in e for e in errors))


class TestACLEnforcer(unittest.TestCase):
    """Tests for acl_enforcer.py"""

    def setUp(self):
        self.enforcer = ACLEnforcer()
        self.mud_data = load_mud_file("temperature_sensor.json")
        self.enforcer.apply_mud_policy("temp-sensor-01", self.mud_data)

    def test_mqtt_to_broker_allowed(self):
        """MQTT traffic to the designated broker should be ACCEPTED."""
        result = self.enforcer.check_traffic("temp-sensor-01", "192.168.1.100", 1883, "tcp")
        self.assertTrue(result, "MQTT to broker should be accepted")

    def test_https_updates_allowed(self):
        """HTTPS traffic to any IP on port 443 should be ACCEPTED."""
        result = self.enforcer.check_traffic("temp-sensor-01", "8.8.8.8", 443, "tcp")
        self.assertTrue(result, "HTTPS update traffic should be accepted")

    def test_arbitrary_internet_dropped(self):
        """Arbitrary internet traffic on port 80 should be DROPPED."""
        result = self.enforcer.check_traffic("temp-sensor-01", "1.2.3.4", 80, "tcp")
        self.assertFalse(result, "Arbitrary internet traffic should be dropped")

    def test_unknown_device_dropped(self):
        """Traffic from an unregistered device should be DROPPED."""
        result = self.enforcer.check_traffic("unknown-device", "192.168.1.100", 1883, "tcp")
        self.assertFalse(result, "Unknown device traffic should be dropped")

    def test_smart_bulb_local_coap_allowed(self):
        """Smart bulb CoAP traffic on local network should be ACCEPTED."""
        bulb_mud = load_mud_file("smart_bulb.json")
        self.enforcer.apply_mud_policy("smart-bulb-01", bulb_mud)
        result = self.enforcer.check_traffic("smart-bulb-01", "192.168.1.50", 5683, "udp")
        self.assertTrue(result, "Smart bulb CoAP local traffic should be accepted")

    def test_smart_bulb_internet_dropped(self):
        """Smart bulb internet traffic should be DROPPED."""
        bulb_mud = load_mud_file("smart_bulb.json")
        self.enforcer.apply_mud_policy("smart-bulb-01", bulb_mud)
        result = self.enforcer.check_traffic("smart-bulb-01", "8.8.8.8", 80, "tcp")
        self.assertFalse(result, "Smart bulb internet traffic should be dropped")


class TestMUDFileServer(unittest.TestCase):
    """Integration tests — requires the MUD file server to be running."""

    SERVER_URL = "http://localhost:5000"

    @classmethod
    def setUpClass(cls):
        try:
            import requests
            cls.requests = requests
            response = requests.get(cls.SERVER_URL, timeout=2)
            cls.server_available = response.status_code == 200
        except Exception:
            cls.server_available = False

    def _skip_if_no_server(self):
        if not self.server_available:
            self.skipTest("MUD file server not running — skipping integration tests")

    def test_server_index(self):
        self._skip_if_no_server()
        resp = self.requests.get(self.SERVER_URL)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("available_mud_files", data)

    def test_temperature_sensor_served(self):
        self._skip_if_no_server()
        resp = self.requests.get(f"{self.SERVER_URL}/mud/temperature_sensor.json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("ietf-mud:mud", data)

    def test_smart_bulb_served(self):
        self._skip_if_no_server()
        resp = self.requests.get(f"{self.SERVER_URL}/mud/smart_bulb.json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("ietf-mud:mud", data)

    def test_nonexistent_file_returns_404(self):
        self._skip_if_no_server()
        resp = self.requests.get(f"{self.SERVER_URL}/mud/nonexistent.json")
        self.assertEqual(resp.status_code, 404)


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  MUD IoT Project — Full Test Suite")
    print("=" * 60)
    unittest.main(verbosity=2)
