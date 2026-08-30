# OpenPort Exporter — Helm Chart

*Helm chart for deploying the **OpenPort Exporter** on Kubernetes.*

Upstream project: https://github.com/renatogalera/openport-exporter

## Overview

The exporter periodically scans IPs/CIDRs with **Nmap** and exposes **low-cardinality Prometheus metrics** so you can alert when ports **open/close**. 

> **Binding**: the exporter binds using `LISTEN_PORT` (env) / `--listen.port` (flag).  
> `config.server.port` is parsed for validation but **does not bind** the server. This chart sets `LISTEN_PORT` for you.

## Prerequisites

- Kubernetes **1.20+**
- Helm **v3**
- (Optional) Prometheus Operator for `ServiceMonitor`
- Container image must include **`nmap`** (the published image already does)

## Quick Start

```bash
helm install my-openport-exporter oci://ghcr.io/renatogalera/openport-exporter 
```

### Custom values

```bash
helm install my-openport-exporter oci://ghcr.io/renatogalera/openport-exporter -f custom-values.yaml
```

Check status:

```bash
kubectl get pods,svc -l app.kubernetes.io/name=openport-exporter
```

## Configuration

See [`values.yaml`](./values.yaml) for the full set. Key options:

| Key                        | Default      | Description                                            |
| -------------------------- | ------------ | ------------------------------------------------------ |
| `listenPort`               | `9919`       | Container **listening** port (sets `LISTEN_PORT` env)  |
| `metrics.path`             | `/metrics`   | Metrics path (also injected into `METRICS_PATH`)       |
| `service.type`             | `ClusterIP`  | Service type                                           |
| `service.port`             | `9919`       | Service port (can differ from `listenPort` if desired) |
| `containerSecurityContext` | `{}`         | Add `NET_RAW` for SYN scans                            |
| `serviceMonitor.enabled`   | `false`      | Create a `ServiceMonitor`                              |
| `config`                   | *(see file)* | Exporter configuration, mounted at `/app/config.yaml`  |

### Scheduled scans and background details

`config.targets` schedules recurring Nmap scans. In contrast,
`config.background_details.targets` is only an allowlist for presence-only
`openport_port_open` series; it never schedules scans. A recurring detail rule
must overlap a scheduled target by network, protocol, and port. Results from a
Tasks API scan may also populate the allowlist.

```yaml
config:
  targets:
    - name: ssh-network
      target: 192.168.1.0/24
      port_range: "22"
      protocol: tcp
      interval: 1h
  background_details:
    enabled: true
    series_budget: 2000
    ttl: 30m
    include_alias: true
    include_ip: true
    targets:
      - alias: ssh-bastion-primary
        cidr: 192.168.1.10/32
        protocol: tcp
        ports: ["22"]
```

`interval` controls scan cadence. `ttl` is the expiry baseline; scheduled state
uses `max(ttl, 3 × interval)`, so the example above retains state for at least
three hours. A detail value of `1` means the latest accepted successful state
reported the port open. Confirmed closure removes it immediately, while scan
failures retain the last successful state until TTL. Setting `include_alias` or
`include_ip` to `false` keeps the corresponding label with an empty value;
without IP, series collapse by alias, port, and protocol.

The exporter logs a warning for rules with no scheduled overlap, while keeping
them valid for API-only scans. `series_budget` applies independently to each pod.

### Security (NET\_RAW for SYN)

SYN scans (`use_syn_scan: true`) need `CAP_NET_RAW`:

```yaml
containerSecurityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    add: ["NET_RAW"]
```

If you switch to `connect()` (`use_syn_scan: false`), remove `NET_RAW`.

### Ingress

```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: openport.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - hosts: ["openport.example.com"]
      secretName: openport-tls
```

### ServiceMonitor

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
```

## Metrics

* `openport_scan_target_ports_open{target,port_range,protocol}` *(Gauge)*
* `openport_last_scan_duration_seconds{target,port_range,protocol}` *(Gauge)*
* `openport_scan_duration_seconds_bucket` *(Histogram; enable with `duration_metrics: true`)*
* `openport_nmap_scan_timeouts_total{target,port_range,protocol}` *(Counter)*
* `openport_nmap_hosts_up{target,port_range,protocol}` *(Gauge)*
* `openport_nmap_hosts_down{target,port_range,protocol}` *(Gauge)*
* `openport_scans_successful_total{target,port_range,protocol}` *(Counter)*
* `openport_scans_failed_total{target,port_range,protocol,error_type}` *(Counter)*
* `openport_last_scan_timestamp_seconds{target,port_range,protocol}` *(Gauge)*
* `openport_port_state_changes_total{target,port_range,protocol,change_type}` *(Counter)*
* `openport_port_open{alias,ip,port,protocol}` *(presence-only Gauge)*
* `openport_details_series_dropped_total` *(Counter)*
* Scheduler/Tasks:

  * `openport_scheduler_queue_size`
  * `openport_scheduler_running`
  * `openport_scheduler_oldest_pending_seconds`
  * `openport_tasks_created_total{module}`
  * `openport_tasks_completed_total{module,outcome}`
  * `openport_task_duration_seconds_bucket`

## Operations

* Config changes roll via **checksum** annotation (rolling update).
* `/metrics`, `/-/healthy`, `/-/ready` exposed on `listenPort`.
* `/-/reload` accepts **loopback only**.

## Tasks API (on-demand scans)

Protect with `NetworkPolicies` and `config.auth`. Examples:

```bash
# Create
curl -sS -X POST http://openport:9919/v1/tasks/scan \
  -H 'Content-Type: application/json' \
  -d '{"targets":["10.0.0.0/24"],"ports":"22,80","protocol":"tcp","priority":"high"}'

# Get
curl -sS http://openport:9919/v1/tasks/<task_id>

# Cancel
curl -sS -X POST http://openport:9919/v1/tasks/<task_id>/cancel
```

Guards: client allowlist, global/per-IP rate-limiting, series guard, backpressure, per-module caps.

## Development

```bash
helm lint .
helm template my-openport . -f custom-values.yaml
helm upgrade --install my-openport . -n monitoring --create-namespace
```

## License

MIT
