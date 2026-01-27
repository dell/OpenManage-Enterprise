# Kafka Alert and Telemetry Troubleshooting Guide

> **Purpose**: Comprehensive troubleshooting guide for Dell OpenManage Enterprise Kafka-based alert and telemetry pipeline.

---

## Table of Contents
1. [Overview](#overview)
2. [Pipeline-Specific Containers](#pipeline-specific-containers)
3. [Quick Setup](#quick-setup)
4. [Common Issues](#common-issues)
5. [Diagnostic Tools](#diagnostic-tools)
6. [Step-by-Step Troubleshooting](#step-by-step-troubleshooting)
7. [Emergency Procedures](#emergency-procedures)
8. [Ports & Logs](#ports--logs)

---

## Overview

The Kafka alert/telemetry system consists of:
- **Vector**: Alert and telemetry collection agent
- **Kafka**: Message broker for telemetry and alerts
- **VictoriaMetrics**: Telemetry storage and querying
- **VictoriaLogs**: Alert storage and querying
- **Grafana**: Visualization and alerting

### Key Components
```
OME → Vector → Kafka → VictoriaMetrics/VictoriaLogs → Grafana
```

---

### Pipeline-Specific Containers
| Pipeline  | Vector     | Kafka       | Storage         | Grafana | Console/UI |
|-----------|------------|-------------|-----------------|---------|------------|
| **Alerts**| vector_alerts | kafka_alerts(9092) | victorialogs   | grafana_alerts (3000) | redpanda_alerts (8080) |
| **Telemetry** | vector_telemetry | kafka_telemetry(9093) | victoriametrics | grafana_telemetry (3080) | redpanda_telemetry (8090) |

### Macros for Commands
Replace variables in ALL commands:
- `${SERVICE}`: e.g., `vector_alerts` or `kafka_alerts` (full list above)
- `${PIPELINE}`: `alerts` or `telemetry`
- `${TOPIC}`: `alerts` or `telemetry`
- `${STORAGE_PORT}`: `9428` (VictoriaLogs) or `8428` (VictoriaMetrics)
- `${GRAFANA_PORT}`: `3000` or `3080`
- `${GROUP}`: `vector-group`

---

## Quick Setup

### Variable Setup
```powershell
# For Alerts pipeline
PIPELINE="alerts"
SERVICE="kafka_alerts"
TOPIC="alerts"
STORAGE_PORT=9428
GRAFANA_PORT=3000
GROUP="vector-group"

# For Telemetry pipeline
PIPELINE="telemetry"
SERVICE="kafka_telemetry"
TOPIC="telemetry"
STORAGE_PORT=8428
GRAFANA_PORT=3080
GROUP="vector-group"
```

## Common Issues
- Data not in Grafana: Vector down, Kafka empty, ingestion fail, datasource bad, time mismatch, label errors.
- Vector bottlenecks, query perf, resource exhaustion. [docs.victoriametrics](https://docs.victoriametrics.com/victoriametrics/troubleshooting/)

## Diagnostic Tools

### Vector (per pipeline)
```bash
docker logs ${SERVICE} --tail 50 | grep ${PIPELINE}
docker exec ${SERVICE} vector validate /etc/vector/vector.yaml
```

### Kafka (per pipeline)
```bash
docker exec ${SERVICE} /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092

docker exec ${SERVICE} /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

docker exec ${SERVICE} /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --group ${GROUP}

docker exec ${SERVICE} /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic ${TOPIC}
```

### VictoriaMetrics/VictoriaLogs Diagnostics
```bash
curl http://localhost:${STORAGE_PORT}/health
curl http://localhost:${STORAGE_PORT}/metrics | grep storage
```

### Grafana
```bash
# Check datasource connection

# Option 1: Use basic auth (easier)
curl -u admin:admin http://localhost:${GRAFANA_PORT}/api/datasources

# Option 2: Use API token (more secure)
# First create token: http://localhost:${GRAFANA_PORT}/api-keys
# Then use: curl -H "Authorization: Bearer $GRAFANA_TOKEN" http://localhost:${GRAFANA_PORT}/api/datasources
```

## Step-by-Step Troubleshooting

### Phase 1: Service Health
```bash
docker ps -a | grep -E "(vector|kafka|victoria|grafana|redpanda)_${PIPELINE}"
docker logs ${SERVICE} --tail 100  # Repeat for each service
```

### Phase 2: Data Flow
```bash
# Vector sending?
docker logs vector_${PIPELINE} --tail 50 | grep ${PIPELINE}

# Kafka messages?
docker exec kafka_${PIPELINE} /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic ${TOPIC} --max-messages 1

# Verify Storage metrics?
curl http://localhost:${STORAGE_PORT}/metrics | findstr storage

# Verify Grafana Datasource
curl -u admin:admin http://localhost:${GRAFANA_PORT}/api/datasources
```

### Phase 3: Resources
```bash
df -h
docker system df
```

### Phase 4: Config Validation
```bash
docker exec vector_${PIPELINE} vector validate /etc/vector/vector.yaml
docker exec kafka_${PIPELINE} /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic ${TOPIC}
```

## Emergency Procedures

### Complete Pipeline Recovery
```bash
# 1. Stop all services and remove volumes
docker-compose down -v

# 2. Restart services
docker-compose up -d

# 3. Verify health
sleep 30
docker ps
curl http://localhost:${STORAGE_PORT}/health
curl http://localhost:${STORAGE_PORT}/health
curl http://localhost:${GRAFANA_PORT}/api/health
```
## Ports & Logs
| Service          | Port(s)     | Log Path              |
|------------------|-------------|-----------------------|
| Vector           | 8686/8687  | /var/log/vector/     |
| Kafka            | 29092/29093| /opt/kafka/logs/     |
| VictoriaMetrics  | 8428       | /var/log/victoria-metrics/ |
| VictoriaLogs     | 9428       | /var/log/victoria-logs/   |
| Grafana          | 3000/3080  | /var/log/grafana/    |
