## OME Integration with Kafka

### Overview

This repository shows examples of how to visualize OME [telemetry](./Metrics/README.md) and [alerts](./Alerts/README.md) sent to a Kafka broker in Grafana dashboards. It uses open-source components such as Vector, VictoriaMetrics, and VictoriaLogs to transform and store data from Kafka for visualization in Grafana.

Note: This solution is intended as a reference/example. It is not a comprehensive collection of all possible Grafana visualizations.

### Prerequisites

- **OME**: Version 4.6 or above
- **Docker** (with Docker Compose) or **Podman** (with podman-compose)

### Authors

- Mohiadeen Ameer
- Aayush Sharma