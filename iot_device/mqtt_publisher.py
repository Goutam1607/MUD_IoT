"""
mqtt_publisher.py — Publishes sensor data via MQTT
Uses the paho-mqtt library to connect to a broker and publish JSON payloads.
Falls back to simulated output if the broker is unavailable.
"""

import json
import time

try:
    import paho.mqtt.client as mqtt
    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False


class MQTTPublisher:
    def __init__(self, broker: str, port: int = 1883, client_id: str = "mud-iot-device"):
        self.broker = broker
        self.port = port
        self.client_id = client_id
        self.client = None
        self.connected = False
        self._setup_client()

    def _setup_client(self):
        """Initialize and connect the MQTT client."""
        if not PAHO_AVAILABLE:
            print("[MQTT] paho-mqtt not installed — running in simulation mode.")
            return

        self.client = mqtt.Client(client_id=self.client_id)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_publish = self._on_publish

        try:
            print(f"[MQTT] Connecting to broker {self.broker}:{self.port}...")
            self.client.connect(self.broker, self.port, keepalive=60)
            self.client.loop_start()
            time.sleep(1)  # Allow connection to establish
        except Exception as e:
            print(f"[MQTT] ⚠️  Could not connect to broker: {e}")
            print("[MQTT] Falling back to simulation mode.")

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            print(f"[MQTT] ✅ Connected to broker {self.broker}:{self.port}")
        else:
            print(f"[MQTT] ❌ Connection failed with return code {rc}")

    def _on_disconnect(self, client, userdata, rc):
        self.connected = False
        print(f"[MQTT] Disconnected from broker (rc={rc})")

    def _on_publish(self, client, userdata, mid):
        print(f"[MQTT] ✅ Message published (mid={mid})")

    def publish(self, topic: str, payload: dict, qos: int = 1):
        """Publish a JSON payload to the given MQTT topic."""
        payload_str = json.dumps(payload)

        if self.client and self.connected:
            result = self.client.publish(topic, payload_str, qos=qos)
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                print(f"[MQTT] 📤 Published to '{topic}': {payload_str}")
            else:
                print(f"[MQTT] ❌ Publish failed (rc={result.rc})")
        else:
            # Simulation mode
            print(f"[MQTT] 🔵 [SIM] Would publish to '{topic}':")
            print(f"         {payload_str}")

    def disconnect(self):
        """Cleanly disconnect from the broker."""
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
            print("[MQTT] Disconnected.")


if __name__ == "__main__":
    # Quick standalone test
    publisher = MQTTPublisher("192.168.1.100", 1883)
    test_payload = {
        "device_id": "temp-sensor-01",
        "temperature_c": 24.5,
        "humidity_pct": 55.0,
        "timestamp": "2025-01-15T10:00:00Z"
    }
    publisher.publish("iot/temp-sensor-01/temperature", test_payload)
    time.sleep(1)
    publisher.disconnect()
