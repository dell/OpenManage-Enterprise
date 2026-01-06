# Alerts Visualization Documentation

OME sends the alerts data to Kafka in a specific format. Refer to the format [here](./omeKafkaALERTS.json). For showing this alerts information in Grafana, one of the possible ways is to store the data in a log storing platform like victoria-logs. To format the data as required by victoria-logs, we can use a solution like vector.

The solution shown here assumes a docker setup to create container instances of these components and integrates them through necessary configuration files like [vector.yaml](vector/vector.yaml).

## Note

For ease of reproducing, the solution has a [producer.py](./producer.py) script which generates the alerts in the necessary format and sends to Kafka. In actual setup, the alerts will be sent by OME, so the producer script can be avoided and the Kafka endpoints need to be replaced in vector configuration.
