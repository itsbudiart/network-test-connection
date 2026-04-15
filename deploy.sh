podman-compose down
podman rmi network-test-connection:latest
podman build -t network-test-connection:latest .
podman-compose up -d --build