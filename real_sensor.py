import adafruit_dht
import board
import paho.mqtt.client as mqtt
import time
import json
from datetime import datetime

DHT_SENSOR  = adafruit_dht.DHT11(board.D4)
BROKER_IP   = "localhost"   # Mosquitto runs on this Pi
BROKER_PORT = 1883
TOPIC       = "sensors/temperature"

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[SENSOR] Connected to MQTT broker at {BROKER_IP}:{BROKER_PORT}")
        print(f"[SENSOR] MUD policy ALLOWS this — port 1883 to {BROKER_IP}")
    else:
        print(f"[SENSOR] Connection FAILED rc={rc}")

client = mqtt.Client(client_id="DHT11-Sensor-v2")
client.on_connect = on_connect
client.connect(BROKER_IP, BROKER_PORT, keepalive=60)
client.loop_start()
time.sleep(1)

reading_no = 0
print("[SENSOR] Reading every 10 seconds. Press Ctrl+C to stop.\n")

while True:
    try:
        temperature = DHT_SENSOR.temperature
        humidity    = DHT_SENSOR.humidity

        if temperature is not None and humidity is not None:
            reading_no += 1
            payload = json.dumps({
                "device":      "DHT11 Temperature Sensor",
                "reading_no":  reading_no,
                "temperature": round(float(temperature), 1),
                "humidity":    round(float(humidity), 1),
                "unit":        "Celsius",
                "timestamp":   datetime.now().isoformat()
            })
            result = client.publish(TOPIC, payload, qos=1)
            print(f"[SENSOR] Reading #{reading_no}")
            print(f"         Temperature : {temperature:.1f} C")
            print(f"         Humidity    : {humidity:.1f} %")
            print(f"         Published   : {'OK' if result.rc == 0 else 'FAILED'}")
            print()
        else:
            print("[SENSOR] Sensor returned None — retrying...")
            time.sleep(3)
            continue

    except RuntimeError as e:
        print(f"[SENSOR] Read error (retrying): {e}")
        time.sleep(3)
        continue

    time.sleep(10)
