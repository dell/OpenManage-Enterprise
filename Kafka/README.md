# OME Integration with Kafka

## Overview

This repository provides reference implementations for visualizing OME data sent to a Kafka broker using Grafana dashboards.

| Solution | Description | Stack |
|----------|-------------|-------|
| [Telemetry](./Telemetry/README.md) | Time-series metrics visualization | Kafka → Vector → VictoriaMetrics → Grafana |
| [Alerts](./Alerts/README.md) | Log-based alert visualization | Kafka → Vector → VictoriaLogs → Grafana |

> **Note**: These solutions are intended as reference examples. They are not comprehensive collections of all possible Grafana visualizations.

## Prerequisites

- **OME** 4.6 or above
- **Docker** with Docker Compose, or **Podman** with podman-compose

## Getting Started

Each solution is self-contained with its own `docker-compose.yml`. See the respective README for setup instructions.

## Authors

- Mohiadeen Ameer
- Aayush Sharma