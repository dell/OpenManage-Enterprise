# Telemetry Visualization Documentation

OME sends telemetry data to Kafka in a specific format. Refer to the format [here](./producer/app/Telemetry2.json). To visualize telemetry in Grafana, the data can be converted into time-series metrics and stored in a database such as VictoriaMetrics. Vector is used to transform the Kafka payloads into metrics.

This solution uses Docker Compose to start the full pipeline using [docker-compose.yml](docker-compose.yml) and [vector.yaml](vector/vector.yaml). Vector sends metrics to VictoriaMetrics using the Prometheus Remote Write protocol, and Grafana queries VictoriaMetrics via its Prometheus-compatible datasource. (A Prometheus server is not deployed as part of this stack, but the pipeline can be adapted to Prometheus if needed.)

## Note

For ease of reproducing, the solution includes a containerized Python producer (see [producer.py](./producer/app/producer.py)) that generates sample telemetry payloads and publishes them to Kafka when you run `docker compose up`.

In an actual setup, OME publishes telemetry directly to Kafka. In that case, you can disable or remove the `ome_telemetry_producer` service in `docker-compose.yml`.

If you are integrating with an existing Kafka deployment (instead of the local Kafka container), you can also disable or remove the `kafka` and `redpanda` services, and update the Kafka endpoints in `vector/vector.yaml` (and any other services that reference `kafka:9092`) to point to your Kafka cluster.

## Run with Docker Compose

From this directory:

```bash
# Start (build + run)
docker compose up -d --build

# Stop
docker compose down

# Clean reset (removes volumes)
docker compose down -v
```

### Useful endpoints

- **Grafana**: `http://localhost:3080`
- **Vector API**: `http://localhost:8686`
- **VictoriaMetrics UI/API**: `http://localhost:8428`
- **Kafka (host access)**: `localhost:29093`
- **Redpanda Console (Kafka UI)**: `http://localhost:8090`
