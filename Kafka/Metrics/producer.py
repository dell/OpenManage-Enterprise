import json
import time
import random
from datetime import datetime, timedelta
from kafka import KafkaProducer

# Load the original telemetry data
with open("Telemetry2.json", "r") as f:
    original_data = json.load(f)

# Kafka setup
producer = KafkaProducer(
    bootstrap_servers='localhost:29092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

topic = 'telemetry'
n_times = 100  # Change this to how many times you want to send the data
interval_sec = 5  # Time between sends

def get_iso_utc_timestamp():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

# Helper to update timestamps and values in-place
def update_telemetry_data(data):
    updated_data = json.loads(json.dumps(data))  # Deep copy
    for system in updated_data.get("System", []):
        for metric in system.get("Metric", []):
            # Update timestamp(s)
            metric["TimeStamp"] = [get_iso_utc_timestamp()]

            # Update metric values (simulate change)
            new_values = []
            for val in metric.get("MetricValue", []):
                try:
                    val = float(val)
                    val = round(val * random.uniform(0.95, 1.05), 2)
                    new_values.append(val)
                except (ValueError, TypeError):
                    new_values.append(val)  # Leave non-numeric as-is
            metric["MetricValue"] = new_values
    return updated_data

# Send data N times
for i in range(n_times):
    updated = update_telemetry_data(original_data)
    producer.send(topic, updated)
    print(f"[{i+1}/{n_times}] Sent telemetry data with updated values and timestamps.")
    time.sleep(interval_sec)
