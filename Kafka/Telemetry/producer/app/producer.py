"""
#### Synopsis
Publishes simulated telemetry data to a Kafka topic.

#### Description
The script reads telemetry from a JSON file, updates timestamps and metric
values, and sends the data to Kafka at fixed intervals for testing purposes.

#### Usage
Recommended (container): run `docker compose up` from the Telemetry stack directory.

Local (for debugging): `python producer.py`
"""

import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Dict, Any, Final

try:
    from kafka import KafkaProducer
    from kafka.errors import NoBrokersAvailable
except ModuleNotFoundError as error:
    print(
        "This program requires kafka-python. To install it on most systems run: "
        "`pip install kafka-python`"
    )
    raise error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------
KAFKA_BOOTSTRAP_SERVERS: Final[str] = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:29092")
KAFKA_TOPIC: Final[str] = os.getenv("KAFKA_TOPIC", "telemetry")
TELEMETRY_FILE: Final[str] = os.getenv("TELEMETRY_FILE", "Telemetry2.json")

SEND_COUNT: Final[int] = int(os.getenv("SEND_COUNT", "100"))
SEND_INTERVAL_SEC: Final[int] = int(os.getenv("SEND_INTERVAL_SECONDS", "5"))
KAFKA_CONNECT_RETRY_SECONDS: Final[int] = int(os.getenv("KAFKA_CONNECT_RETRY_SECONDS", "5"))

TIMESTAMP_FORMAT: Final[str] = "%Y%m%dT%H%M%SZ"
FILE_ENCODING: Final[str] = "utf-8"

METRIC_VARIATION_MIN: Final[float] = 0.95
METRIC_VARIATION_MAX: Final[float] = 1.05
METRIC_DECIMAL_PLACES: Final[int] = 2


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
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


def update_telemetry_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep copy telemetry data and update timestamps and metric values.

    Args:
        data (Dict[str, Any]): Original telemetry data structure.

    Returns:
        Dict[str, Any]: Updated telemetry data with new timestamps and randomized metric values.
    """
    updated_data = json.loads(json.dumps(data))

    for system in updated_data.get("System", []):
        for metric in system.get("Metric", []):
            metric["TimeStamp"] = [get_custom_utc_timestamp()]

            updated_values = []
            for value in metric.get("MetricValue", []):
                try:
                    numeric_value = float(value)
                    updated_values.append(round(numeric_value * random.uniform(METRIC_VARIATION_MIN, METRIC_VARIATION_MAX), METRIC_DECIMAL_PLACES))
                except (ValueError, TypeError):
                    updated_values.append(value)

            metric["MetricValue"] = updated_values

    return updated_data


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
                value_serializer=lambda value: json.dumps(value).encode(FILE_ENCODING),
            )
        except NoBrokersAvailable:
            LOGGER.warning(
                "Kafka not reachable at %s. Retrying in %ss...",
                KAFKA_BOOTSTRAP_SERVERS,
                KAFKA_CONNECT_RETRY_SECONDS,
            )
            time.sleep(KAFKA_CONNECT_RETRY_SECONDS)


# ---------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------
def main() -> None:
    """
    Main execution loop for sending telemetry data to Kafka.

    Returns:
        None
    """
    with open(TELEMETRY_FILE, "r", encoding=FILE_ENCODING) as file_handle:
        original_data: Dict[str, Any] = json.load(file_handle)

    producer: KafkaProducer = create_kafka_producer()

    try:
        iteration: int = 0
        while SEND_COUNT <= 0 or iteration < SEND_COUNT:
            updated_payload: Dict[str, Any] = update_telemetry_data(original_data)
            producer.send(KAFKA_TOPIC, updated_payload)

            LOGGER.info(
                "[%s/%s] Sent telemetry update",
                iteration + 1,
                SEND_COUNT if SEND_COUNT > 0 else "∞",
            )

            iteration += 1
            time.sleep(SEND_INTERVAL_SEC)

    finally:
        producer.flush()
        producer.close()


if __name__ == "__main__":
    main()
