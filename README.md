# OpenPort Exporter

*A low-cardinality, abuse-resistant Prometheus exporter that maps **open ports** across IPs/CIDRs using **Nmap**, with an optional **/probe** endpoint for on-demand checks.*

[GitHub: renatogalera/openport-exporter](https://github.com/renatogalera/openport-exporter)

---

## Table of Contents

* [Why OpenPort Exporter](#why-openport-exporter)
* [Architecture](#architecture)
* [Quick Start](#quick-start)

  * [Binary](#binary)
  * [Docker](#docker)
  * [Kubernetes (example)](#kubernetes-example)
* [Configuration](#configuration)

  * [Config file (`config.yaml`)](#config-file-configyaml)
  * [Flags & Environment variables](#flags--environment-variables)
* [HTTP Endpoints](#http-endpoints)

  * [/metrics (exporter metrics)](#metrics-exporter-metrics)
  * [/probe (optional, Blackbox-style)](#probe-optional-blackboxstyle)
* [Metrics](#metrics)

  * [Exporter metrics (namespace `openport_`)](#exporter-metrics-namespace-openport_)
  * [Probe response metrics (ephemeral)](#probe-response-metrics-ephemeral)
* [Prometheus Scrape Configs](#prometheus-scrape-configs)

  * [Exporter](#exporter)
  * [/probe job (targets via relabel)](#probe-job-targets-via-relabel)
* [Security & Hardening](#security--hardening)
* [Operational Guidance](#operational-guidance)

  * [SLOs & Alerts](#slos--alerts)
  * [Performance & Tuning](#performance--tuning)
  * [Troubleshooting](#troubleshooting)
* [Development](#development)
* [License](#license)

---

## Why OpenPort Exporter

* **Safe by default**: `/probe` is **disabled** unless explicitly enabled. Rate limits, concurrency caps, and allow-lists built in.
* **Cardinality-aware**: background `/metrics` exports **aggregates**, not per-IP/port series. Per-port details are available only from `/probe` on demand.
* **Correct Prometheus semantics**: no heavy work in `Collect()`, explicit HELP/TYPE, bounded labels, scrape timeout respected.
* **Operationally boring**: context propagation, deterministic shutdown, guarded goroutines, structured logs (Go `slog`).

---

## Architecture

```
+-------------------------+
| Config (YAML / flags)   |
+-----------+-------------+
            |
            v
+-----------+-------------+       +-----------------------------+
| Scheduler / Worker Pool |  -->  | Nmap (SYN or connect/UDP)  |
| (bounded queue & ctx)   |       +-----------------------------+
+-----------+-------------+
            |
            v
+-------------------------+
| Metrics Store (aggreg.) |
| openport_* gauges/cntrs |
+-----------+-------------+
            |
            v
+-------------------------+        +----------------------------+
| HTTP Server             |        | Optional: /probe handler   |
| /metrics, /-/healthy    |        | (rate/conc/allow-lists)    |
| /-/ready                |        +----------------------------+
+-------------------------+
```

* Background workers periodically scan configured targets and publish **aggregated** metrics.
* The **/probe** endpoint (optional) runs an on-demand *one-off* scan and returns **probe-scoped** metrics only.

---

## Quick Start

### Binary

```bash
# Build
go build -o openport-exporter ./cmd

# Run with defaults (listens on :9919, reads config.yaml in cwd)
./openport-exporter
```

> **Note**
> TCP **SYN** scan is the default (fast, low connection overhead). It requires `CAP_NET_RAW`. If you set `use_syn_scan: false`, the exporter will use `connect()` scan and requires no special capability (slower/noisier).

### Docker

```bash
# Example: allow SYN scan inside container (non-root + CAP_NET_RAW is recommended)
docker run --rm -p 9919:9919 \
  --cap-add=NET_RAW \
  -v $PWD/config.yaml:/config.yaml:ro \
  -e CONFIG_PATH=/config.yaml \
  ghcr.io/renatogalera/openport-exporter:latest
```

---

### Kubernetes (example)

Use chart located at [./chart](./chart/README.md).

---

## Configuration

### Config file (`config.yaml`)

Below is a concise, **source-of-truth** example. Defaults shown reflect the codebase.

```yaml
server:
  port: 9919       # NOTE: current listener uses flag LISTEN_PORT; this field is reserved.

scanning:
  interval: 10800          # seconds; <600 is rejected and replaced by 10800 (3h)
  port_range: "1-65535"
  max_cidr_size: 24        # split CIDRs wider than this (e.g., /16 -> /24 chunks)
  timeout: 3600            # per-subnet scan timeout (seconds)
  duration_metrics: false
  disable_dns_resolution: true
  udp_scan: false
  use_syn_scan: true       # default true; requires CAP_NET_RAW if true

  # Bounded worker model
  rate_limit: 60           # reserved
  task_queue_size: 100
  worker_count: 5

  # Nmap tuning (safe defaults)
  min_rate: 1000
  max_rate: 0              # 0 = unlimited
  min_parallelism: 1000
  max_retries: 6
  host_timeout: 300
  scan_delay: 0
  max_scan_delay: 0
  initial_rtt_timeout: 0
  max_rtt_timeout: 0
  min_rtt_timeout: 0
  disable_host_discovery: true

# Background targets (IP or CIDR)
targets:
  - 192.168.10.0/24

# Optional /probe runtime policy
prober:
  enabled: false
  allow_cidrs: []            # targets allow-list (CIDRs)
  client_allow_cidrs: []     # caller IP allow-list (CIDRs)
  rate_limit: 1.0            # req/sec
  burst: 1
  max_cidr_size: 24
  max_concurrent: 1
  default_timeout: "10s"
  max_ports: 4096
  max_targets: 32
  auth_token: ""             # if set: require Authorization: Bearer <token>
  basic_user: ""             # optional Basic Auth
  basic_pass: ""
  modules:                   # optional presets referenced via ?module=name
    fast_syn:
      protocol: tcp
      ports: "22-80"
      use_syn_scan: true
      min_rate: 2000
      min_parallelism: 1000
      max_retries: 3
      host_timeout: 180
      disable_host_discovery: true
```

> **Implementation note**
> The listener actually binds using the **flag/env** `LISTEN_PORT`. `server.port` is validated but not currently used to bind.

### Flags & Environment variables

All flags have environment overrides (via `viper`). Common ones:

| Flag                         | Env                         |       Default | Description                         |
| ---------------------------- | --------------------------- | ------------: | ----------------------------------- |
| `--metrics.path`             | `METRICS_PATH`              |    `/metrics` | Metrics endpoint path               |
| `--listen.port`              | `LISTEN_PORT`               |        `9919` | HTTP listen port                    |
| `--address`                  | `ADDRESS`                   |   `localhost` | Shown on root page                  |
| `--config.path`              | `CONFIG_PATH`               | `config.yaml` | YAML config path                    |
| `--collector.go`             | `ENABLE_GO_COLLECTOR`       |       `false` | Enable Go runtime metrics           |
| `--collector.build_info`     | `ENABLE_BUILD_INFO`         |        `true` | Build info metric                   |
| `--prober.enable`            | `ENABLE_PROBER`             |       `false` | Enable `/probe`                     |
| `--prober.allow_cidr`        | `PROBER_ALLOW_CIDRS`        |          `[]` | Target CIDR allow-list (repeatable) |
| `--prober.client_allow_cidr` | `PROBER_CLIENT_ALLOW_CIDRS` |          `[]` | Caller CIDR allow-list              |
| `--prober.rate_limit`        | `PROBER_RATE_LIMIT`         |         `1.0` | Requests/sec                        |
| `--prober.burst`             | `PROBER_BURST`              |           `1` | Token bucket burst                  |
| `--prober.max_cidr_size`     | `PROBER_MAX_CIDR_SIZE`      |          `24` | Split cap for target CIDRs          |
| `--prober.max_concurrent`    | `PROBER_MAX_CONCURRENT`     |           `1` | Concurrent `/probe` limit           |
| `--prober.default_timeout`   | `PROBER_DEFAULT_TIMEOUT`    |         `10s` | Default per-probe timeout           |
| `--prober.max_ports`         | `PROBER_MAX_PORTS`          |        `4096` | Safety cap on ports param           |
| `--prober.max_targets`       | `PROBER_MAX_TARGETS`        |          `32` | Safety cap on targets param         |
| `--prober.auth_token`        | `PROBER_AUTH_TOKEN`         |          `""` | Bearer token to require             |
| `--prober.basic_user`        | `PROBER_BASIC_USER`         |          `""` | Basic auth user                     |
| `--prober.basic_pass`        | `PROBER_BASIC_PASS`         |          `""` | Basic auth pass                     |
| `--log.level`                | `LOG_LEVEL`                 |        `info` | `debug`/`info`/`warn`/`error`       |
| `--log.format`               | `LOG_FORMAT`                |        `json` | `json` or `text`                    |

---

## HTTP Endpoints

### `/metrics` (exporter metrics)

* Fast, constant-time; **no I/O** on request path.
* Includes:

  * Background scan metrics (`openport_*`)
  * Build/go collectors (if enabled)
  * **Admin probe handler metrics**: `openport_probe_requests_total`, `openport_probe_inflight`, `openport_probe_handler_seconds`

Health endpoints:

* `/-/healthy` → `200 OK`
* `/-/ready`   → `200 OK` (ready as soon as server is up)

### `/probe` (optional, Blackbox-style)

Disabled by default. When enabled:

**Query params**

* `target` (required): comma/space-separated list of IPs or CIDRs
* `ports` (required): `22,80,443` or `1000-1024`
* `protocol` (optional): `tcp` (default) or `udp`
* `timeout` (optional): e.g., `5s` (will be clamped by request header & server policy)
* `details` (optional): `1` to include per-(ip,port,proto) gauges in the response
  *Guard*: request is **rejected** if `estimatedIPs * ports > 5000` series.
* `max_cidr_size` (optional): tighten split fan-out for the request
* `module` (optional): apply a preset from `prober.modules`

**Security & abuse resistance**

* **Caller allow-list** (`--prober.client_allow_cidr`); deny by default if set.
* **Target allow-list** (`--prober.allow_cidr`); deny by default if set.
* **Rate limiting** (`rate_limit` + `burst`)
* **Concurrency cap** (`max_concurrent`)
* **Auth**: either **Bearer** (`Authorization: Bearer …`) or **Basic** (`user/pass`) may be configured.

**Scrape-timeout honoring**

* The handler reads `X-Prometheus-Scrape-Timeout-Seconds` and **shrinks** internal deadline by a safety margin.

> `/probe` returns a **separate, per-request registry**, so probe metrics do not pollute exporter series.

---

## Metrics

### Exporter metrics (namespace `openport_`)

| Metric                                  | Type      | Labels                                   | Description                                                               |
| --------------------------------------- | --------- | ---------------------------------------- | ------------------------------------------------------------------------- |
| `openport_scan_target_ports_open_total` | Gauge     | `target,port_range,protocol`             | Open (ip,port,proto) count **in last scan** for that target/range/proto   |
| `openport_last_scan_duration_seconds`   | Gauge     | `target,port_range,protocol`             | Duration of last scan (seconds)                                           |
| `openport_scan_duration_seconds`        | Histogram | `target,port_range,protocol`             | Distribution of scan durations                                            |
| `openport_task_queue_size`              | Gauge     | *none*                                   | Current task queue size                                                   |
| `openport_nmap_scan_timeouts_total`     | Counter   | `target,port_range,protocol`             | Nmap scans that timed out                                                 |
| `openport_nmap_host_up_count`           | Gauge     | `target`                                 | Hosts up in last scan (target scope)                                      |
| `openport_nmap_host_down_count`         | Gauge     | `target`                                 | Hosts down in last scan                                                   |
| `openport_scans_successful_total`       | Counter   | `target,port_range,protocol`             | Completed without error                                                   |
| `openport_scans_failed_total`           | Counter   | `target,port_range,protocol,error_type`  | Failed scans broken down by `error_type` (`timeout`,`permission`,`other`) |
| `openport_last_scan_timestamp_seconds`  | Gauge     | `target,port_range,protocol`             | Unix ts of last scan                                                      |
| `openport_port_state_changes_total`     | Counter   | `target,port_range,protocol,change_type` | `closed_to_open` / `open_to_closed`                                       |

**Probe handler admin metrics** (also on `/metrics`):

* `openport_probe_requests_total{outcome=…}` with outcomes like `ok`, `bad_request`, `unauthorized`, `target_denied`, `rate_limited`, `concurrency`, `series_limit`, `large_fanout`, `error`
* `openport_probe_inflight` (gauge)
* `openport_probe_handler_seconds` (histogram)

### Probe response metrics (ephemeral)

These appear **only** in the `/probe` HTTP response:

| Metric                                | Type  | Labels             | Notes                                              |
| ------------------------------------- | ----- | ------------------ | -------------------------------------------------- |
| `probe_success`                       | Gauge | *none*             | 1 on success, 0 on error                           |
| `probe_duration_seconds`              | Gauge | *none*             | Average per-target duration within the request     |
| `probe_open_ports_total`              | Gauge | *none*             | Count of open (ip,port,proto) tuples found         |
| `probe_hosts_up` / `probe_hosts_down` | Gauge | *none*             | Host reachability per request                      |
| `probe_port_open`                     | Gauge | `ip,port,protocol` | Only when `details=1` and series limit checks pass |

---

## Prometheus Scrape Configs

### Exporter

```yaml
scrape_configs:
  - job_name: 'openport_exporter'
    static_configs:
      - targets: ['openport-exporter:9919']
    metrics_path: /metrics
```

### `/probe` job (targets via relabel)

The `/probe` endpoint is a **prober**: it returns metrics scoped to the request, not exporter state.

**TCP reachability on selected ports**

```yaml
scrape_configs:
  - job_name: 'openport_probe_tcp'
    metrics_path: /probe
    static_configs:
      - targets:
          - "10.0.0.0/24"
          - "10.0.1.10"
    params:
      ports: ["22,80,443"]
      protocol: ["tcp"]
      timeout: ["10s"]
      details: ["0"]
    relabel_configs:
      # Pass original target as ?target=
      - source_labels: [__address__]
        target_label: __param_target
      # Route scrape to exporter
      - target_label: __address__
        replacement: openport-exporter:9919
    # Optional: add bearer token header
    authorization:
      type: Bearer
      credentials: YOUR_TOKEN
```

**UDP example**

```yaml
  - job_name: 'openport_probe_udp53'
    metrics_path: /probe
    static_configs:
      - targets: ["10.0.2.0/24"]
    params:
      ports: ["53"]
      protocol: ["udp"]
      timeout: ["5s"]
```

> Keep `/probe` QPS low and ensure allow-lists & auth are configured.

---

## Security & Hardening

* **Principle of least privilege**

  * SYN scan (`use_syn_scan: true`) requires `CAP_NET_RAW`. Run container **as non-root** with only `NET_RAW`.
  * If `use_syn_scan: false`, no capability is needed (slower `connect()` scan).
* **Network policy**

  * Use **egress** policies to limit scan destinations to intended CIDRs.
* **/probe abuse resistance**

  * Enable **client & target allow-lists**, **rate limiting**, and **concurrency caps**.
  * Requests with `details=1` are rejected if they would exceed **5k** time series.
* **Transport**

  * Place behind a TLS-terminating reverse proxy if exposed.
  * Avoid HTTP/2 cleartext exposure on the internet.
* **Secrets hygiene**

  * No secrets in metrics or logs; avoid logging full targets when sensitive.
  * Prefer **Bearer** over Basic; if using Basic, rotate credentials.
* **Supply chain**

  * Pin dependencies and run `govulncheck`, `staticcheck`, `gosec` in CI.

---

## Operational Guidance

### SLOs & Alerts

* **Availability**: `/metrics` served within scrape timeout.
* **Latency**: `openport_probe_handler_seconds` p95 < **1s** (tune per environment).
* **Backpressure**: `openport_task_queue_size` steady-state near **0**.

**Alert suggestions**

```promql
# Exporter unhealthy (scrapes failing)
up{job="openport_exporter"} == 0

# Probe handler saturation
sum(rate(openport_probe_requests_total{outcome=~"rate_limited|concurrency"}[5m])) > 0

# Scan runtime anomalies (p95 increase)
histogram_quantile(0.95, sum(rate(openport_scan_duration_seconds_bucket[10m])) by (le)) > 60

# Exposure changed abruptly
increase(openport_port_state_changes_total[15m]) > 0
```

### Performance & Tuning

* Start with defaults. Increase `min_rate`/`min_parallelism` gradually; cap with `max_rate`.
* Keep `worker_count` modest; this exporter is I/O bound by Nmap.
* Consider `disable_host_discovery: true` (equivalent to `-Pn`) **only** when you’re confident hosts are up.

### Troubleshooting

* **Permission errors** with SYN scan → ensure `CAP_NET_RAW`.
* **Slow scans** → reduce port ranges; tune `min_rate`, `max_retries`, `host_timeout`.
* **Probe rejections** → check `allow_cidrs`, `client_allow_cidrs`, and series limits (details=1).

---

## Development

```bash
# Build & run
go build ./...
./openport-exporter --log.level=debug

# Tests (race + coverage)
go test -race -v ./...

# Static analysis (examples)
golangci-lint run
govulncheck ./...
staticcheck ./...
gosec ./...
```

---

## License

Licensed under the [MIT](./LICENSE).
