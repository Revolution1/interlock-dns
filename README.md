# interlock-dns

Only works in Docker 1.12+ swarm mode.

## quick start

1. [Start Interlock with docker services](https://github.com/ehazlett/interlock/tree/swarm-services/docs/examples/nginx-services)
2. run interlock-dns

```
docker service create --name dns -p 53:53/udp -p 53:53 \
    --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
    --constraint 'node.role == manager' --mode global\
    daocloud.io/revolution1/interlock-dns
```

## Environments

```
BIND_PORT       int     default: 53
BIND_IP         string  default: 0.0.0.0
POLL_INTERVAL   string  default: 3s [support: 0.5,1s,1m,1h] float
DNS_TTL         string  default: 5s [support: 5,1s,1m,1h]   integer
```