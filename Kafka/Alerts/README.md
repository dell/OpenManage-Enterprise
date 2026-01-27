# Alerts Visualization

## Overview

OME sends alert data to Kafka in a specific JSON format (see [sample payload](./producer/app/omeKafkaALERTS.json)). This solution visualizes those alerts in Grafana by storing them in [VictoriaLogs](https://docs.victoriametrics.com/victorialogs/), a high-performance log storage backend.

[Vector](https://vector.dev/) transforms and forwards Kafka messages to VictoriaLogs (see [vector.yaml](vector/vector.yaml)).

## Quick Start

From this directory:

```bash
docker compose up -d --build
```

Open Grafana at http://localhost:3000 to view the alerts dashboard.

```bash
docker compose down      # Stop
docker compose down -v   # Stop and remove volumes
```

## Architecture

```
Kafka → Vector → VictoriaLogs → Grafana
```

## Endpoints

| Service | URL |
|---------|-----|
| Grafana | http://localhost:3000 |
| VictoriaLogs | http://localhost:9428 |
| Redpanda Console | http://localhost:8080 |
| Vector API | http://localhost:8687 |
| Kafka (host) | localhost:29092 |

## Notes

- **Troubleshooting**: For operational issues and diagnostics, see the [Kafka Troubleshooting Guide](../troubleshooting-guide.md#alerts-pipeline).

- **Sample Producer**: A containerized Python producer ([producer.py](./producer/app/producer.py)) generates sample alerts for demonstration. In production, OME publishes alerts directly to Kafka—disable or remove the `ome_alerts_producer` service in [docker-compose.yml](docker-compose.yml).

- **Existing Kafka Cluster**: To integrate with an existing Kafka deployment, remove the `kafka` and `redpanda` services and update `kafka:9092` references in [vector.yaml](vector/vector.yaml) to point to your cluster.
