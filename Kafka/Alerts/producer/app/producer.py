"""
#### Synopsis
Publishes simulated alert data to a Kafka topic.

#### Description
This script loads alert data from a JSON file, updates selected fields,
and publishes the data periodically to a Kafka topic.

#### Usage
Recommended (container): run `docker compose up` from the Alerts stack directory.

Local (for debugging): `python producer.py`
"""

import json
import os
import time
import random
from datetime import datetime
from typing import List, Dict, Any, Final

try:
    from kafka import KafkaProducer
    from kafka.errors import NoBrokersAvailable
except ModuleNotFoundError as error:
    print(
        "This program requires kafka-python. To install it on most systems run: "
        "`pip install kafka-python`"
    )
    raise error

# -----------------------------
# Constants
# -----------------------------
ALERT_DATA_FILE: Final[str] = "omeKafkaALERTS.json"
KAFKA_BOOTSTRAP_SERVERS: Final[str] = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:29092")
KAFKA_TOPIC: Final[str] = os.getenv("KAFKA_TOPIC", "alerts")

SEND_COUNT: Final[int] = int(os.getenv("SEND_COUNT", "100"))
SEND_INTERVAL_SECONDS: Final[int] = int(os.getenv("SEND_INTERVAL_SECONDS", "5"))
KAFKA_CONNECT_RETRY_SECONDS: Final[int] = int(os.getenv("KAFKA_CONNECT_RETRY_SECONDS", "5"))

ALERT_IDENTIFIERS: Final[List[str]] = ["6SXV903", "7TXW104", "8UYZ205", "9VZA306"]
EEMI_MESSAGE_IDS: Final[List[str]] = [f"CDEV12{i:02d}" for i in range(10)]

# -----------------------------
# Utility Functions
# -----------------------------


def get_custom_utc_timestamp() -> str:
    """
    Get the current UTC time formatted as a compact string without separators.

    Returns:
        str: Current UTC time in the format YYYYMMDDTHHMMSSZ.
    """
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def load_alert_data(file_path: str) -> Dict[str, Any]:
    """
    Load alert data from a JSON file.

    Args:
        file_path (str): Path to the JSON file.

    Returns:
        dict: Parsed alert data.
    """
    with open(file_path, "r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def create_kafka_producer() -> KafkaProducer:
    """
    Create and return a Kafka producer instance.

    Returns:
        KafkaProducer: Configured Kafka producer.
    """
    while True:
        try:
            return KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda value: json.dumps(value).encode("utf-8"),
            )
        except NoBrokersAvailable:
            print(
                f"Kafka not reachable at {KAFKA_BOOTSTRAP_SERVERS}. "
                f"Retrying in {KAFKA_CONNECT_RETRY_SECONDS}s..."
            )
            time.sleep(KAFKA_CONNECT_RETRY_SECONDS)


def update_alert_data(
    data: Dict[str, Any],
    alert_id_index: int,
    eemi_id_index: int,
) -> Dict[str, Any]:
    """
    Update alert fields with rotating identifiers and randomized values.

    Args:
        data (dict): Original alert data.
        alert_id_index (int): Index for rotating AlertIdentifier.
        eemi_id_index (int): Index for rotating EEMIMessageId.

    Returns:
        dict: Updated alert data.
    """
    updated_data: Dict[str, Any] = json.loads(json.dumps(data))

    for alert in updated_data.get("Data", []):
        alert["Timestamp"] = get_custom_utc_timestamp()
        alert["UpdatedTimeStamp"] = get_custom_utc_timestamp()
        alert["Severity"] = random.choice([4, 6, 8, 10])
        alert["IsAcknowledged"] = random.choice([True, False])
        alert["AlertIdentifier"] = ALERT_IDENTIFIERS[
            alert_id_index % len(ALERT_IDENTIFIERS)
        ]
        alert["EEMIMessageId"] = EEMI_MESSAGE_IDS[
            eemi_id_index % len(EEMI_MESSAGE_IDS)
        ]

    return updated_data


# -----------------------------
# Main Execution
# -----------------------------
def main() -> None:
    """
    Main execution loop for sending alert data to Kafka.

    Returns:
        None
    """
    alert_data: Dict[str, Any] = load_alert_data(ALERT_DATA_FILE)
    producer: KafkaProducer = create_kafka_producer()

    alert_id_index: int = 0
    eemi_id_index: int = 0

    try:
        iteration: int = 0
        while SEND_COUNT <= 0 or iteration < SEND_COUNT:
            updated_data: Dict[str, Any] = update_alert_data(
                alert_data,
                alert_id_index,
                eemi_id_index,
            )

            producer.send(KAFKA_TOPIC, updated_data)

            print(
                f"[{iteration + 1}/{SEND_COUNT if SEND_COUNT > 0 else '∞'}] "
                f"Sent alert data with "
                f"AlertIdentifier={ALERT_IDENTIFIERS[alert_id_index % len(ALERT_IDENTIFIERS)]} "
                f"and EEMIMessageId={EEMI_MESSAGE_IDS[eemi_id_index % len(EEMI_MESSAGE_IDS)]}"
            )

            alert_id_index += 1
            eemi_id_index += 1
            iteration += 1
            time.sleep(SEND_INTERVAL_SECONDS)

    finally:
        producer.flush()
        producer.close()


if __name__ == "__main__":
    main()
