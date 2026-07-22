import paho.mqtt.client as mqtt
import time, json, random
from colorama import Fore, init
init(autoreset=True)

MUD_URL = "http://localhost:5000/mud/temperature_sensor.json"
BROKER  = "localhost"
PORT    = 1883
TOPIC   = "sensors/temperature"


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"{Fore.GREEN}[DEVICE] Connected to MQTT Broker!")
        print(f"{Fore.CYAN}[DEVICE] My MUD URL: {MUD_URL}")
    else:
        print(f"{Fore.RED}[DEVICE] Connection failed with code: {rc}")


def simulate_device():
    print(f"{Fore.CYAN}[DEVICE] Temperature Sensor v2 starting up...")
    print(f"{Fore.CYAN}[DEVICE] Broadcasting MUD URL via DHCP: {MUD_URL}")
    print(f"{Fore.YELLOW}[DEVICE] (In real hardware, this goes in DHCP Option 161)")

    client = mqtt.Client(client_id="temperature_sensor_01")
    client.on_connect = on_connect

    try:
        client.connect(BROKER, PORT, 60)
        client.loop_start()
        time.sleep(2)

        print(f"\n{Fore.GREEN}[DEVICE] Starting to publish sensor data...")
        for i in range(10):
            temp  = round(random.uniform(20.0, 35.0), 2)
            humid = round(random.uniform(40.0, 80.0), 2)
            payload = json.dumps({
                "device_id":   "sensor_01",
                "temperature": temp,
                "humidity":    humid,
                "unit":        "celsius",
                "timestamp":   time.time()
            })
            client.publish(TOPIC, payload)
            print(f"{Fore.GREEN}[DEVICE] Published -> Temp: {temp}C, Humidity: {humid}%")
            time.sleep(3)

        client.loop_stop()
        client.disconnect()
        print(f"\n{Fore.YELLOW}[DEVICE] Simulation complete.")

    except ConnectionRefusedError:
        print(f"{Fore.RED}[DEVICE] ERROR: Cannot connect to MQTT broker.")
        print(f"{Fore.YELLOW}[DEVICE] Make sure Mosquitto is running: sudo service mosquitto start")


if __name__ == "__main__":
    simulate_device()
