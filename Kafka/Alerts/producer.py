import json
import time
import random
from datetime import datetime
from kafka import KafkaProducer

# Load the alert data
with open("omeKafkaALERTS Change set.2025-09-18T13%3A34%3A47.871823.json", "r") as f:
    alert_data = json.load(f)

# Kafka setup
producer = KafkaProducer(
    bootstrap_servers='localhost:29092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

topic = 'alerts'
n_times = 100         # Number of sends
interval_sec = 5     # Interval between sends

def get_iso_utc_timestamp():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

# Pools for rotating identifiers
alert_identifiers = ["6SXV903", "7TXW104", "8UYZ205", "9VZA306"]
eemi_message_ids = [f"CDEV12{i:02d}" for i in range(10)]

# Rotation counters
alert_id_index = 0
eemi_id_index = 0

def update_alert_data(data, alert_id_index, eemi_id_index):
    updated_data = json.loads(json.dumps(data))  # Deep copy
    for alert in updated_data.get("Data", []):
        alert["Timestamp"] = get_iso_utc_timestamp()
        alert["UpdatedTimeStamp"] = get_iso_utc_timestamp()
        alert["Severity"] = random.choice([4, 6, 8, 10])
        alert["IsAcknowledged"] = random.choice([True, False])
        alert["AlertIdentifier"] = alert_identifiers[alert_id_index % len(alert_identifiers)]
        alert["EEMIMessageId"] = eemi_message_ids[eemi_id_index % len(eemi_message_ids)]
    return updated_data

# Send data to Kafka
for i in range(n_times):
    updated = update_alert_data(alert_data, alert_id_index, eemi_id_index)
    producer.send(topic, updated)
    print(f"[{i+1}/{n_times}] Sent alert data with AlertIdentifier={alert_identifiers[alert_id_index % len(alert_identifiers)]} and EEMIMessageId={eemi_message_ids[eemi_id_index % len(eemi_message_ids)]}.")
    alert_id_index += 1
    eemi_id_index += 1
    time.sleep(interval_sec)
