# OpenPort Exporter Helm Chart

*A production-ready Helm chart for deploying **OpenPort Exporter** on Kubernetes, following safe-by-default, cardinality-aware, and abuse-resistant.*

**Upstream project:** [renatogalera/openport-exporter](https://github.com/renatogalera/openport-exporter)

---

## Table of Contents

* [Overview](#overview)
* [Prerequisites](#prerequisites)
* [Quick Start](#quick-start)

  * [Add repository](#add-repository)
  * [Install](#install)
  * [Upgrade](#upgrade)
  * [Uninstall](#uninstall)
* [Chart Structure](#chart-structure)
* [Configuration](#configuration)

  * [Values reference (excerpt)](#values-reference-excerpt)
  * [Config file (`values.yaml` → `config.yaml`)](#config-file-valuesyaml--configyaml)
  * [Security context (NET\_RAW for SYN scan)](#security-context-net_raw-for-syn-scan)
  * [Ingress](#ingress)
  * [ServiceMonitor (Prometheus Operator)](#servicemonitor-prometheus-operator)
* [Prometheus Scraping Examples](#prometheus-scraping-examples)

  * [Exporter scrape](#exporter-scrape)
  * [/probe scrape (Blackbox-style)](#probe-scrape-blackbox-style)
* [Metrics](#metrics)
* [Security & Hardening](#security--hardening)
* [Operations](#operations)

  * [SLOs & Alerts](#slos--alerts)
  * [Tuning & Performance](#tuning--performance)
  * [Troubleshooting](#troubleshooting)
* [Development](#development)
* [License](#license)

---

## Overview

**OpenPort Exporter** periodically scans IPs/CIDRs using **Nmap** and exposes **low-cardinality Prometheus metrics**. An optional **`/probe`** endpoint enables on-demand, per-request scans with strict safety controls (rate limiting, concurrency caps, allow-lists).

This chart ships batteries included:

* Kubernetes manifests for **Deployment**, **Service**, **ConfigMap**, **PodDisruptionBudget**, **Ingress**, and **ServiceMonitor** (optional).
* Enterprise knobs: tolerations, affinities, pod/container **SecurityContexts**, and resource limits.
* Clean separation of **background metrics** vs **ephemeral probe output**.

> Authentication for `/metrics` and `/probe` is handled at the **Kubernetes layer** (NetworkPolicies, ServiceMesh, or an authenticated Ingress). The exporter also supports optional Basic/Bearer for `/probe`.

---

## Prerequisites

* **Kubernetes** ≥ 1.20
* **Helm** v3
* **(Optional)** Prometheus Operator if you want `ServiceMonitor`

---

## Quick Start

### Add repository

```bash
helm repo add openport-repo https://example.com/openport-exporter
helm repo update
```

### Install

```bash
helm install my-openport-exporter openport-repo/openport-exporter
# or with your overrides
helm install my-openport-exporter openport-repo/openport-exporter -f custom-values.yaml
```

Check status:

```bash
kubectl get pods,svc,deploy -l app.kubernetes.io/name=openport-exporter
```

### Upgrade

```bash
helm upgrade my-openport-exporter openport-repo/openport-exporter -f custom-values.yaml
```

### Uninstall

```bash
helm uninstall my-openport-exporter
```

---

## Chart Structure

```
openport-exporter/
├── Chart.yaml
├── templates/
│   ├── _helpers.tpl
│   ├── configmap.yaml
│   ├── deployment.yaml
│   ├── ingress.yaml
│   ├── pdb.yaml
│   ├── service.yaml
│   └── servicemonitor.yaml
└── values.yaml
```

* **Chart.yaml** – chart metadata.
* **templates/** – rendered Kubernetes objects.
* **values.yaml** – default configuration; override via `-f your-values.yaml`.

---

## Configuration

### Values reference (excerpt)

> See `values.yaml` for all options and inline docs. Key settings below:

| Key                                     | Type    | Default                                  | Description                                       |
| --------------------------------------- | ------- | ---------------------------------------- | ------------------------------------------------- |
| `image.repository`                      | string  | `ghcr.io/renatogalera/openport-exporter` | Container image                                   |
| `image.tag`                             | string  | chart `appVersion`                       | Image tag                                         |
| `image.pullPolicy`                      | string  | `IfNotPresent`                           | Pull policy                                       |
| `replicaCount`                          | int     | `1`                                      | Deployment replicas                               |
| `service.type`                          | string  | `ClusterIP`                              | Service type                                      |
| `service.port`                          | int     | `9919`                                   | Service port                                      |
| `extraArgs`                             | list    | `[]`                                     | Extra CLI flags to exporter                       |
| `extraEnv`                              | list    | `[]`                                     | Extra environment variables                       |
| `resources`                             | object  | requests/limits set                      | CPU/memory requests & limits                      |
| `podSecurityContext`                    | object  | `{}`                                     | Pod-level security context                        |
| `containerSecurityContext`              | object  | `{}`                                     | Container-level security (add `NET_RAW` for SYN)  |
| `nodeSelector`,`tolerations`,`affinity` | objects | `{}`                                     | Scheduling controls                               |
| `readinessProbe.*` / `livenessProbe.*`  | object  | enabled                                  | Health probes (`/-/ready`,`/-/healthy`)           |
| `serviceMonitor.enabled`                | bool    | `false`                                  | Create ServiceMonitor                             |
| `ingress.enabled`                       | bool    | `false`                                  | Create Ingress                                    |
| `config`                                | object  | see below                                | **Exporter config** (rendered into `config.yaml`) |

### Config file (`values.yaml` → `config.yaml`)

The chart mounts `values.yaml:config` into the container as `/app/config.yaml`. Example (abridged; defaults align with exporter):

```yaml
config:
  server:
    port: 9919
  scanning:
    interval: 10800
    port_range: "1-65535"
    max_cidr_size: 24
    timeout: 3600
    duration_metrics: true
    disable_dns_resolution: true
    udp_scan: false
    use_syn_scan: true
    task_queue_size: 100
    worker_count: 5

    # Nmap tuning
    min_rate: 1000
    max_rate: 0
    min_parallelism: 1000
    max_retries: 6
    host_timeout: 300
    scan_delay: 0
    max_scan_delay: 0
    initial_rtt_timeout: 0
    max_rtt_timeout: 0
    min_rtt_timeout: 0
    disable_host_discovery: true

  # Background targets
  targets:
    - "192.168.1.0/24"
    - "10.0.0.0/24"

  # Optional /probe (safer via YAML than flags)
  prober:
    enabled: false
    allow_cidrs: []
    client_allow_cidrs: []
    rate_limit: 1
    burst: 1
    max_cidr_size: 24
    max_concurrent: 1
    default_timeout: "10s"
    max_ports: 4096
    max_targets: 32
    auth_token: ""
    basic_user: ""
    basic_pass: ""
    modules:
      tcp_syn_fast:
        protocol: tcp
        ports: "22,80,443,1000-1024"
        use_syn_scan: true
        min_rate: 2000
        min_parallelism: 1000
        max_retries: 3
        host_timeout: 180
        disable_host_discovery: true
```

> **Port note**
> The exporter binds to the port set by the **flag/env** `--listen.port` / `LISTEN_PORT`. By default the chart does not set this flag; the exporter uses **9919**. Keep `service.port` and `config.server.port` consistent with the actual listen port.

### Security context (NET\_RAW for SYN scan)

SYN mode (`use_syn_scan: true`) needs `CAP_NET_RAW`. Enable it in the container security context and keep the pod non-root:

```yaml
containerSecurityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    add: ["NET_RAW"]
```

If you switch to `connect()` scan (`use_syn_scan: false`) you can **remove** `NET_RAW`.

### Ingress

Expose the service externally (optionally with TLS):

```yaml
ingress:
  enabled: true
  className: "nginx"
  host: "openport.example.com"
  annotations: {}
  tls: []
```

> Protect `/metrics` and especially `/probe` with your ingress controller’s auth (e.g., OAuth2 proxy) or perimeter firewalls.

### ServiceMonitor (Prometheus Operator)

Create a ServiceMonitor to scrape `/metrics`:

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
  labels: {}
  annotations: {}
  namespace: ""   # leave empty to use release ns
```

---

## Prometheus Scraping Examples

### Exporter scrape

**ServiceMonitor** (Operator):

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: openport-exporter
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: openport-exporter
  endpoints:
    - port: metrics
      path: /metrics
      interval: 30s
      scrapeTimeout: 10s
```

### `/probe` scrape (Blackbox-style)

`/probe` is an on-demand prober; keep QPS low and use allow-lists + auth.

**Prometheus (static config) example:**

```yaml
scrape_configs:
  - job_name: 'openport_probe_tcp'
    metrics_path: /probe
    params:
      ports: ["22,80,443"]
      protocol: ["tcp"]
      timeout: ["10s"]
      details: ["0"]
    static_configs:
      - targets:
          - "10.0.0.0/24"
          - "10.0.1.10"
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - target_label: __address__
        replacement: openport-exporter:9919
```

**ServiceMonitor** equivalent (Operator):

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: openport-probe
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: openport-exporter
  endpoints:
    - port: metrics
      path: /probe
      interval: 1m
      scrapeTimeout: 15s
      params:
        ports: ["22,80,443"]
        protocol: ["tcp"]
        timeout: ["10s"]
        details: ["0"]
      relabelings:
        - sourceLabels: [__address__]
          targetLabel: __param_target
        - targetLabel: __address__
          replacement: openport-exporter:9919
  targetLabels: []
```

> If you gate `/probe` with a bearer token, configure the Prometheus instance (or Operator) to inject the header.

---

## Metrics

Exporter (background) metrics use the **`openport_`** namespace and are **cardinality-bounded**:

* `openport_scan_target_ports_open_total{target,port_range,protocol}` (Gauge)
* `openport_last_scan_duration_seconds{target,port_range,protocol}` (Gauge)
* `openport_scan_duration_seconds{target,port_range,protocol}` (Histogram)
* `openport_task_queue_size` (Gauge)
* `openport_nmap_scan_timeouts_total{target,port_range,protocol}` (Counter)
* `openport_nmap_host_up_count{target}`, `openport_nmap_host_down_count{target}` (Gauges)
* `openport_scans_successful_total{target,port_range,protocol}` (Counter)
* `openport_scans_failed_total{target,port_range,protocol,error_type}` (Counter)
* `openport_last_scan_timestamp_seconds{target,port_range,protocol}` (Gauge)
* `openport_port_state_changes_total{target,port_range,protocol,change_type}` (Counter)

Probe handler admin metrics (also on `/metrics`):

* `openport_probe_requests_total{outcome=...}`
* `openport_probe_inflight` (Gauge)
* `openport_probe_handler_seconds` (Histogram)

**Ephemeral `/probe` response metrics** (per-request):

* `probe_success` (Gauge), `probe_duration_seconds` (Gauge),
  `probe_open_ports_total` (Gauge), `probe_hosts_up`, `probe_hosts_down` (Gauges),
  `probe_port_open{ip,port,protocol}` (Gauge; only with `details=1`, bounded)

---

## Security & Hardening

* **Least privilege**: run as non-root; if SYN scan, add only `NET_RAW`.
* **NetworkPolicies**: restrict **egress** to intended CIDRs; restrict **ingress** to Prometheus and trusted systems.
* **/probe protections**: enable client/target **allow-lists**, **rate limiting**, **concurrency caps**, and **auth** (Bearer/Basic).
* **Transport**: prefer TLS termination at ingress/mesh. Avoid exposing over the public internet without auth.
* **Secrets**: do not log sensitive targets; avoid exposing internal topologies via world-readable endpoints.

---

## Operations

### SLOs & Alerts

* **Availability**: exporter `/metrics` scrapes succeed within timeout.
* **Latency**: `openport_probe_handler_seconds` p95 within agreed budgets.
* **Backpressure**: `openport_task_queue_size` near 0 under steady state.

Example alerts (PromQL):

```promql
# Exporter down
up{job="openport_exporter"} == 0

# Probe saturation
sum(rate(openport_probe_requests_total{outcome=~"rate_limited|concurrency"}[5m])) > 0

# Scan latency anomaly
histogram_quantile(0.95, sum(rate(openport_scan_duration_seconds_bucket[10m])) by (le)) > 60

# Sudden exposure change
increase(openport_port_state_changes_total[15m]) > 0
```

### Tuning & Performance

* Start with defaults; then gradually increase `min_rate` / `min_parallelism`.
* Keep `worker_count` reasonable; Nmap drives the bottleneck.
* Use `disable_host_discovery: true` (`-Pn`) only when you’re confident targets are up.

### Troubleshooting

* **Permission denied** with SYN scan → add `NET_RAW`.
* **Slow scans** → narrow `port_range`, tune `max_retries`, `host_timeout`, `min_rate`.
* **Probe rejected** → verify allow-lists, rate limits, `max_targets`, `max_ports`, and `details` series limit.

---

## Development

```bash
# Lint chart
helm lint .

# Dry-run template
helm template my-openport-exporter . -f custom-values.yaml

# Install/upgrade in a namespace
helm upgrade --install my-openport-exporter . -n monitoring --create-namespace -f custom-values.yaml
```

---

## License

This chart is released under the [MIT](./LICENSE) license.
