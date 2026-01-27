# Telemetry Visualization

## Overview

OME sends telemetry data to Kafka in a specific JSON format (see [sample payload](./producer/app/Telemetry2.json)). This solution visualizes that telemetry in Grafana by converting it to time-series metrics and storing them in [VictoriaMetrics](https://docs.victoriametrics.com/), a high-performance metrics database.

[Vector](https://vector.dev/) transforms Kafka messages into Prometheus-compatible metrics using the Remote Write protocol (see [vector.yaml](vector/vector.yaml)). Grafana queries VictoriaMetrics via its Prometheus-compatible datasource.

## Quick Start

From this directory:

```bash
docker compose up -d --build
```

Open Grafana at http://localhost:3080 to view the telemetry dashboard.

```bash
docker compose down      # Stop
docker compose down -v   # Stop and remove volumes
```

## Architecture

```
Kafka → Vector → VictoriaMetrics → Grafana
```

## Endpoints

| Service | URL |
|---------|-----|
| Grafana | http://localhost:3080 |
| VictoriaMetrics | http://localhost:8428 |
| Redpanda Console | http://localhost:8090 |
| Vector API | http://localhost:8686 |

## Notes

- **Troubleshooting**: For operational issues and diagnostics, see the [Kafka Troubleshooting Guide](../troubleshooting-guide.md#telemetry-pipeline).

- **Sample Producer**: A containerized Python producer ([producer.py](./producer/app/producer.py)) generates sample telemetry for demonstration. In production, OME publishes telemetry directly to Kafka—disable or remove the `ome_telemetry_producer` service in [docker-compose.yml](docker-compose.yml).

- **Existing Kafka Cluster**: To integrate with an existing Kafka deployment, remove the `kafka` and `redpanda` services and update `kafka:9092` references in [vector.yaml](vector/vector.yaml) to point to your cluster.

- **Prometheus Compatibility**: This stack does not deploy a Prometheus server, but the pipeline can be adapted to use Prometheus instead of VictoriaMetrics if needed.

- **Redpanda Console**: Provides a lightweight Kafka UI so you can browse topics and payloads without installing additional tooling.

- **Grafana Credentials**: Default login is `admin` / `admin`.
