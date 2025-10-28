# Metrics Visualization Documentation

OME sends the metrics data to Kafka in a specific format. Refer the format [here](./Telemetry2.json). For showing this metrics information in Grafana, one of the possible ways is to format the data as a time-series and dump it to a time-series database like prometheus or victoria metrics. To format the data we can use a solution like vector.

The solution shown here assumes a docker setup to create container instances of these components and integrates them through necessary configuration files like [vector.yaml](vector/vector.yaml). The current solution shows the integration through victoria-metrics, but it can easily be replaced with a prometheus configuration. Necessary prometheus scrape configuration is present [here](prometheus/prometheus.yml).

## Note

For ease of reproducing, the solution has a [producer.py](./producer.py) script which generates the alerts in the necessary format and sends to Kafka. In actual setup, the alerts will be sent by OME, so the producer script can be avoided and the Kafka endpoints need to replaced in vector configuration.