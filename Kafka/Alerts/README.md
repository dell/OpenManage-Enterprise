# Alerts Visualization Documentation

OME sends alerts data to Kafka in a specific format. Refer to the format [here](./producer/app/omeKafkaALERTS.json). To visualize alerts in Grafana, the data can be stored in a log storage backend such as VictoriaLogs. Vector is used to transform the Kafka payloads and forward them to VictoriaLogs.

This solution uses Docker Compose to start the full pipeline using [docker-compose.yml](docker-compose.yml) and [vector.yaml](vector/vector.yaml).

## Note

For ease of reproducing, the solution includes a containerized Python producer (see [producer.py](./producer/app/producer.py)) that generates sample alert payloads and publishes them to Kafka when you run `docker compose up`.

In an actual setup, OME publishes alerts directly to Kafka. In that case, you can disable or remove the `ome_alerts_producer` service in `docker-compose.yml`.

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

- **Grafana**: `http://localhost:3000`
- **Vector API**: `http://localhost:8687`
- **VictoriaLogs UI/API**: `http://localhost:9428`
- **Kafka (host access)**: `localhost:29092`
- **Redpanda Console (Kafka UI)**: `http://localhost:8080`
