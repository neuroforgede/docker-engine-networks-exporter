 #!/bin/bash
 docker build -f Dockerfile \
    -t neuroforgede/docker-engine-networks-exporter:latest \
    -t neuroforgede/docker-engine-networks-exporter:0.1 \
    .

docker push neuroforgede/docker-engine-networks-exporter:latest
docker push neuroforgede/docker-engine-networks-exporter:0.1