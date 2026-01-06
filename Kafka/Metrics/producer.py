"""
#### Synopsis
Publishes simulated telemetry data to a Kafka topic.

#### Description
The script reads telemetry from a JSON file, updates timestamps and metric
values, and sends the data to Kafka at fixed intervals for testing purposes.

#### Python Example
`python producer.py`
"""

import json
import logging
import random
import time
from datetime import datetime
from typing import Dict, Any, Final

try:
    from kafka import KafkaProducer
except ModuleNotFoundError as error:
    print(
        "This program requires kafka-python. To install it on most systems run: "
        "`pip install kafka-python`"
    )
    raise error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------
KAFKA_BOOTSTRAP_SERVERS: Final[str] = "localhost:29092"
KAFKA_TOPIC: Final[str] = "telemetry"
TELEMETRY_FILE: Final[str] = "Telemetry2.json"

SEND_COUNT: Final[int] = 100
SEND_INTERVAL_SEC: Final[int] = 5


# ---------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------
def get_custom_utc_timestamp() -> str:
    """
    Get the current UTC time formatted as a compact string without separators.

    Returns:
        str: Current UTC time in the format YYYYMMDDTHHMMSSZ.
    """
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def update_telemetry_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a deep copy of telemetry data and update timestamps and metric values.

    Args:
        data (Dict[str, Any]): Original telemetry data dictionary.

    Returns:
        Dict[str, Any]: A deep-copied and updated telemetry data dictionary,
                        with refreshed timestamps and adjusted metric values.
    """
    updated_data = json.loads(json.dumps(data))  # Deep copy

    for system in updated_data.get("System", []):
        for metric in system.get("Metric", []):
            metric["TimeStamp"] = [get_custom_utc_timestamp()]

            updated_values = []
            for value in metric.get("MetricValue", []):
                try:
                    numeric_value = float(value)
                    updated_values.append(
                        round(numeric_value * random.uniform(0.95, 1.05), 2)
                    )
                except (ValueError, TypeError):
                    updated_values.append(value)

            metric["MetricValue"] = updated_values

    return updated_data


# ---------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------
def main() -> None:
    """
    Load telemetry data from a JSON file and publish updated telemetry to Kafka
    repeatedly at fixed intervals.

    Reads the telemetry data once, then sends updated copies with fresh timestamps
    and metric values to a Kafka topic SEND_COUNT times, sleeping SEND_INTERVAL_SEC
    seconds between sends.

    Returns:
        None
    """
    with open(TELEMETRY_FILE, "r", encoding="utf-8") as file_handle:
        original_data: Dict[str, Any] = json.load(file_handle)

    producer: KafkaProducer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )

    try:
        for index in range(SEND_COUNT):
            updated_payload: Dict[str, Any] = update_telemetry_data(original_data)
            producer.send(KAFKA_TOPIC, updated_payload)

            LOGGER.info(
                "Sent telemetry update %d/%d",
                index + 1,
                SEND_COUNT,
            )

            time.sleep(SEND_INTERVAL_SEC)

    finally:
        producer.flush()
        producer.close()


if __name__ == "__main__":
    main()
