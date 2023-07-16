# Docker engine networks exporter (Docker Engine/Swarm)

![](https://img.shields.io/docker/pulls/neuroforgede/docker-engine-networks-exporter.svg)

*Docker engine networks exporter* exposes docker network infromation to prometheus metrics.

The following metrics are supported:
- docker_network_container_used_ips
- docker_network_service_used_ips
- docker_network_usable_ips


Proudly made by [NeuroForge](https://neuroforge.de/) in Bayreuth, Germany.

## Use in a Docker Swarm deployment

Deploy:

```yaml
version: "3.8"

services:
  docker-engine-networks-exporter:
    image: ghcr.io/neuroforgede/docker-engine-networks-exporter:latest
    networks:
      - net
    environment:
      - DOCKER_HOSTNAME={{.Node.Hostname}}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    deploy:
      mode: global
      resources:
        limits:
          memory: 256M
        reservations:
          memory: 128M
```

prometheus.yml

```yaml
# ...
scrape_configs:
  - job_name: 'docker-engine-networks-exporter'
    dns_sd_configs:
    - names:
      - 'tasks.docker-engine-networks-exporter'
      type: 'A'
      port: 9000
```

A monitoring solution based on the original swarmprom that includes this can be found at our [Swarmsible Stacks repo](https://github.com/neuroforgede/swarmsible-stacks)
