# OpenPort Exporter

**Prometheus exporter for network‑exposure monitoring.**
Periodically scans your IPs/CIDRs using **Nmap** and exposes **low‑cardinality** metrics so you can **detect and alert when ports open or close** on critical hosts.

## Why OpenPort Exporter

* **Cardinality-aware**: background `/metrics` exports **aggregates** (per target/range/protocol), not per-IP/port series. Optional **background details** can emit bounded per-port series for a strict allowlist.
* **Live configuration**: **hot‑reload** via **SIGHUP** or **HTTP** without service interruption. Dynamic TTL management and thread‑safe snapshots.
* **Correct Prometheus semantics**: no heavy work in `Collect()`, clear HELP/TYPE, bounded labels, and scrape timeout honored.
* **Operationally boring**: context propagation, deterministic shutdown, guarded goroutines, structured logs via Go `slog`.

---

## Architecture

```
+-------------------------+
| Config (YAML / flags)   |
+-----------+-------------+
            |
            v
+-----------+-------------+       +-----------------------------+
| ConfigManager (live)    |  <--  | SIGHUP / POST /-/reload     |
| Thread-safe snapshots   |       +-----------------------------+
+-----------+-------------+
            |
            v
+-----------+-------------+       +-----------------------------+
| Scheduler / Worker Pool |  -->  | Nmap (SYN or connect/UDP)   |
| (bounded queue & ctx)   |       +-----------------------------+
+-----------+-------------+
            |
            v
+-------------------------+
| Metrics Store (aggreg.) |
| openport_* gauges/cntrs |
| Dynamic TTL sweeper     |
+-----------+-------------+
            |
            v
+-------------------------+  
| HTTP Server             |
| /metrics, /-/healthy    |
| /-/ready, /-/reload     |
+-------------------------+
```

*Background workers scan configured **targets** at their intervals and publish **aggregated** metrics.*

---

## Quick Start

### Binary

```bash
# Build
go build -o openport-exporter ./cmd

# Run (listens on :9919; reads ./config.yaml by default)
./openport-exporter
```

> **Scan mode:** TCP **SYN** is default (fast/low-overhead) and **requires `CAP_NET_RAW`**.
> Set `use_syn_scan: false` to use `connect()` scans (no capability needed, but slower/noisier).

### Docker

```bash
# Non-root + CAP_NET_RAW recommended for SYN
docker run --rm -p 9919:9919 \
  --cap-add=NET_RAW \
  -v $PWD/config.yaml:/config.yaml:ro \
  -e CONFIG_PATH=/config.yaml \
  ghcr.io/renatogalera/openport-exporter:latest
```

### Kubernetes

A Helm chart is available in `./chart`. See [`chart/README.md`](./chart/README.md) for `values.yaml` and examples (Service, ServiceMonitor, RBAC, etc.).

---

## Configuration

OpenPort Exporter reads a single **YAML** file (default `./config.yaml`).
All fields and defaults below reflect the codebase.

> **Binding:** The process binds using **`--listen.port`** / **`LISTEN_PORT`**.
> `server.port` is parsed/validated but **not** used to bind.

### Minimal example

```yaml
server:
  port: 9919

scanning:
  # We'll scan every 3h by default (see defaults below)
  port_range: "1-65535"
  max_cidr_size: 24
  disable_dns_resolution: true
  use_syn_scan: true

targets:
  - name: "dmz-ssh"
    target: "192.168.10.0/24"
    port_range: "22"
    protocol: "tcp"
    interval: "1h"
```

### Full reference (`config.yaml`)

> **Units**
> Unless stated otherwise: durations use Go syntax (e.g., `30m`, `4h`), timeouts not in duration format are **seconds**, delays in **milliseconds**.

```yaml
server:
  port: 9919                         # validated but NOT used to bind the HTTP server
  trusted_proxies_cidrs: []          # CIDRs allowed to supply X-Forwarded-For (see Security)

scanning:
  interval: 10800                    # seconds; <600 -> replaced by 10800 (3h)
  port_range: "1-65535"              # default ports if target.port_range is empty
  max_cidr_size: 24                  # split CIDRs broader than this (e.g., /16 -> /24)
  timeout: 3600                      # seconds; per-subnet scan timeout
  duration_metrics: false            # when true, emits duration gauge + histogram
  disable_dns_resolution: true       # nmap -n
  udp_scan: false                    # force UDP at config level (task-level protocol also supported)
  use_syn_scan: true                 # true => SYN scan (needs CAP_NET_RAW); false => connect()

  # Bounded worker model (legacy fields; see scheduler.* for queue/worker tuning)
  rate_limit: 60                     # reserved (not used by current scheduler)
  task_queue_size: 100               # fallback if scheduler.task_queue_size <= 0
  worker_count: 5                    # fallback if scheduler.worker_count <= 0

  # Nmap tuning (safe defaults)
  min_rate: 1000
  max_rate: 0                        # 0 = unlimited
  min_parallelism: 1000
  max_retries: 6
  host_timeout: 300                  # seconds
  scan_delay: 0                      # milliseconds
  max_scan_delay: 0                  # milliseconds
  initial_rtt_timeout: 0             # milliseconds
  max_rtt_timeout: 0                 # milliseconds
  min_rtt_timeout: 0                 # milliseconds
  disable_host_discovery: true       # nmap -Pn

# Background targets (per-target interval)
# NOTE: Background targets are OPTIONAL. When omitted, the exporter runs in
# API-only mode (no background scans) and you can trigger scans via the Tasks API.
# NOTE: "module" is currently IGNORED for background scans; modules apply to Task API only.
targets:
  - name: "dmz_ssh"
    target: "192.168.10.0/24"        # IP or CIDR (IPv4 or IPv6)
    port_range: "22"                  # comma/ranges (e.g., "80,443,8000-8010")
    protocol: "tcp"                   # "tcp" | "udp"
    interval: "1h"                    # per-target interval (next eligible after this)
    module: ""                        # (ignored by background scheduler in current release)

# Optional: Background Port Details (allowlisted per-port series with hard cap)
background_details:
  enabled: false
  series_budget: 2000                 # upper bound of concurrently exposed per-port series
  ttl: "30m"                          # TTL for detailed series without reconfirmation
  targets:                            # explicit allowlist of what can emit detail-series
    - alias: "ssh-bastion-primary"    # REQUIRED and unique
      cidr: "203.0.113.10/32"         # IP or CIDR
      protocol: "tcp"                 # "tcp" | "udp" | "" (defaults to tcp)
      ports: ["22"]                   # list of ports or ranges
    - alias: "cluster-etcd"
      cidr: "10.1.1.0/29"
      protocol: "tcp"
      ports: ["2379","2380"]
    - alias: "web-servers-dmz"
      cidr: "198.51.100.0/28"
      protocol: "tcp"
      ports: ["80","443","8000-8010"]
  include_alias: true                 # controls label cardinality for detailed series
  include_ip: true                    # when false, IP label is empty (collapse by alias)

# Authentication (applies to Tasks API only; /metrics and health are unauthenticated)
auth:
  bearer_token: ""                    # if set, require "Authorization: Bearer <token>"
  basic:
    username: ""                      # if any basic.* is set, require valid Basic Auth
    password: ""

# API policy: client allowlist, RPS limiting and concurrency guards (Tasks API only)
policy:
  client_allow_cidrs: ["127.0.0.0/8"] # who may call /v1/tasks/* (with XFF trust rules)
  rate_limit_rps: 2.0                 # global & per-IP token-bucket
  rate_burst: 2
  max_concurrent: 2                   # max concurrent handlers for Tasks API
  series_limit: 250000                # guard: estimated_ips * ports must not exceed this

# Scheduler (background + task fan-out)
scheduler:
  worker_count: 5                     # if <=0, fallback to scanning.worker_count
  task_queue_size: 100                # if <=0, fallback to scanning.task_queue_size
  default_timeout: "30m"              # default scan timeout for Task API
  default_max_cidr_size: 24           # default subnet split for Task API
  dedupe_ttl: "15m"                   # deduplication window for task "dedupe_key"
  task_gc_max: 10000                  # cap stored finished tasks (GC oldest beyond this)
  task_gc_max_age: "24h"              # GC finished tasks older than this
  module_limits:                      # per-module concurrency caps (0 = unlimited)
    default: 0
    tcp_syn_fast: 2

# Module presets (applied ONLY when a Task request sets "module": "...").
# Not applied to background targets in the current release.
modules:
  tcp_syn_fast:
    protocol: tcp                     # optional override
    ports: "22,80,443,1000-1024"      # optional override
    use_syn_scan: true
    min_rate: 2000
    min_parallelism: 1000
    max_retries: 3
    host_timeout: 180
    scan_delay: 0
    max_scan_delay: 0
    initial_rtt_timeout: 0
    max_rtt_timeout: 0
    min_rtt_timeout: 0
    disable_host_discovery: true
```

> **Sweeper TTL**
> Global time‑to‑live for inactive series defaults to **3× scanning interval**.
> If `background_details.ttl` is set, that value becomes the **effective global TTL**.
> TTL changes on reload are applied live to the sweeper.

### Flags & environment

All flags have env overrides (via `viper`):

| Flag                     | Env                   | Default       | Description                   |
| ------------------------ | --------------------- | ------------- | ----------------------------- |
| `--metrics.path`         | `METRICS_PATH`        | `/metrics`    | Metrics endpoint path         |
| `--listen.port`          | `LISTEN_PORT`         | `9919`        | HTTP listen port              |
| `--address`              | `ADDRESS`             | `localhost`   | Shown on the root page        |
| `--config.path`          | `CONFIG_PATH`         | `config.yaml` | YAML config path              |
| `--collector.go`         | `ENABLE_GO_COLLECTOR` | `false`       | Enable Go runtime metrics     |
| `--collector.build_info` | `ENABLE_BUILD_INFO`   | `true`        | Expose Prometheus build\_info |
| `--log.level`            | `LOG_LEVEL`           | `info`        | `debug`/`info`/`warn`/`error` |
| `--log.format`           | `LOG_FORMAT`          | `json`        | `json` or `text`              |

---

## Hot Configuration Reload

OpenPort Exporter supports **live reload** with **zero downtime**:

* **SIGHUP**: reloads from the original `config.path`.
* **HTTP**: `POST /-/reload` (allowed **only from loopback**).
* **Active scans continue**; new config is used for subsequent scan cycles and API requests.
* **Dynamic TTL**: sweeper TTL is recalculated if relevant settings change.

```bash
# Reload via signal (Unix)
kill -SIGHUP $(pgrep openport-exporter)

# Reload via HTTP (loopback only)
curl -X POST http://localhost:9919/-/reload
```

**Reloaded live:**

* Target list (`targets`)
* Per-target intervals and most scanning tunables
* `background_details` (allowlist, include flags, TTL → also updates sweeper)
* `policy.*` and `server.trusted_proxies_cidrs` (affects Tasks API guards)
* `scheduler.module_limits` and API concurrency/limits

**Requires restart:**

* HTTP listen port / TLS / network bindings
* Log level/format (applied at start)
* Enabling Go/build collectors via flags
* Scheduler worker pool size (`scheduler.worker_count`)
* Queue buffer size (`scheduler.task_queue_size`)

> The worker pool and queue are created at startup. Changing them safely at runtime would require a dynamic supervisor and is planned for a future release.

**Background details validity rules:**

* Aliases must be unique.
* Each item must declare a valid IP/CIDR and a valid port list/ranges.
* Invalid rules cause reload to **fail** with a clear error; the previous config remains active.

---

## HTTP Endpoints

### Health & Admin

* `GET /-/healthy` → `200 OK`
* `GET /-/ready` → `503` until ready (≈200ms after start), then `200 OK`
* `POST /-/reload` → reloads configuration; **accepted only from loopback** (not proxied)

### Metrics

* `GET /metrics` (path configurable via `--metrics.path`)
* Fast and constant‑time; **no I/O** happens in the request path.
* Exposes exporter metrics and (optionally) `go_*` and `build_info` collectors.

### Tasks API (background scans on demand)

**All Tasks API endpoints enforce policy/auth:**

* **Auth**: `auth.bearer_token` and/or `auth.basic` (either passes).
* **Client allowlist**: `policy.client_allow_cidrs` (uses `X-Forwarded-For` **only** if the direct client is loopback/unspecified or in `server.trusted_proxies_cidrs`).
* **Rate limit**: `policy.rate_limit_rps`/`rate_burst` (global + per‑IP).
* **Max concurrent**: `policy.max_concurrent`.

Endpoints:

* `POST /v1/tasks/scan`
  Enqueue fan‑out scans. **Request**:

  ```json
  {
    "targets": ["10.0.0.0/24", "10.0.1.10"],
    "ports": "22,80,443",
    "protocol": "tcp",              // default "tcp"
    "module": "tcp_syn_fast",       // optional; applies module preset
    "max_cidr_size": 24,            // optional override (split)
    "timeout": "30m",               // optional per-task duration
    "dedupe_key": "optional-key",   // dedupe window: scheduler.dedupe_ttl
    "priority": "high|normal|low",  // default "normal"
    "retries": 0                    // optional retry attempts with backoff
  }
  ```
  **Response**: `200 OK`

  ```json
  {"task_id":"<id>","accepted":true}
  ```

  Guards & errors:

  * **Series guard**: estimate `ips * ports` ≤ `policy.series_limit` → else **400**.
  * **Backpressure**: queue full (including pending priority queue) → **429**.
  * **Rate limit**: exceeded → **429**.
  * **Auth/allowlist**: **401/403**.
  * **Bad input**: **400** (invalid ports/targets, etc).

* `GET /v1/tasks/{id}` → task record (state/summary/timestamps).

* `POST /v1/tasks/{id}/cancel` → best‑effort cancel; `200` on success, `400` otherwise.

* `GET /v1/tasks?state=pending|running|done&limit=N` → compact listing.

**Notes**

* **Deduplication**: same `dedupe_key` inside the TTL returns the **same `task_id`** with `"accepted": false`.
* **Module limits**: per‑module concurrency caps (`scheduler.module_limits`) are enforced across workers.
* **Module presets** are applied **only** when the task sets `"module": "<name>"`.

---

## Metrics Reference

All metric names below are **exactly** as exported by the current code.

### Exporter metrics (namespace `openport_`)

| Metric                                  | Type      | Labels                                   | Description                                                                       |
| --------------------------------------- | --------- | ---------------------------------------- | --------------------------------------------------------------------------------- |
| `openport_scan_target_ports_open`       | Gauge     | `target,port_range,protocol`             | Count of `(ip,port,proto)` observed **open** in the last scan for that key.       |
| `openport_last_scan_duration_seconds`   | Gauge     | `target,port_range,protocol`             | Duration of the last scan (seconds).                                              |
| `openport_scan_duration_seconds`        | Histogram | `target,port_range,protocol`             | Distribution of scan durations (enabled when `duration_metrics: true`).           |
| `openport_nmap_scan_timeouts_total`     | Counter   | `target,port_range,protocol`             | Nmap scans that timed out.                                                        |
| `openport_nmap_hosts_up`                | Gauge     | `target,port_range,protocol`             | Hosts up in last scan.                                                            |
| `openport_nmap_hosts_down`              | Gauge     | `target,port_range,protocol`             | Hosts down in last scan.                                                          |
| `openport_scans_successful_total`       | Counter   | `target,port_range,protocol`             | Scans completed without error.                                                    |
| `openport_scans_failed_total`           | Counter   | `target,port_range,protocol,error_type`  | Failed scans by `error_type` (`timeout`,`permission`,`other`,`scanner_creation`). |
| `openport_last_scan_timestamp_seconds`  | Gauge     | `target,port_range,protocol`             | Unix timestamp of last successful scan.                                           |
| `openport_port_state_changes_total`     | Counter   | `target,port_range,protocol,change_type` | `closed_to_open` / `open_to_closed`.                                              |
| `openport_port_open`                    | Gauge     | `alias,ip,port,protocol`                 | Background details: 1 if `(alias/ip,port,proto)` is open.                         |
| `openport_details_series_dropped_total` | Counter   | —                                        | Background details: series dropped due to `series_budget`.                        |

### Scheduler / Tasks metrics

| Metric                                      | Type      | Labels           | Description                                       |
| ------------------------------------------- | --------- | ---------------- | ------------------------------------------------- |
| `openport_scheduler_queue_size`             | Gauge     | —                | Current scheduler queue size (pending + fan‑out). |
| `openport_scheduler_running`                | Gauge     | —                | Number of running tasks.                          |
| `openport_scheduler_oldest_pending_seconds` | Gauge     | —                | Age of the oldest pending task.                   |
| `openport_tasks_created_total`              | Counter   | `module`         | Tasks accepted for execution.                     |
| `openport_tasks_completed_total`            | Counter   | `module,outcome` | Tasks completed (\`outcome=success, error\`)      |
| `openport_task_duration_seconds`            | Histogram | `module`         | Runtime of tasks.                                 |
| `openport_scheduler_enqueue_failed_total`   | Counter   | —                | Failed enqueues due to backpressure.              |

### HTTP API metrics

| Metric                        | Type    | Labels `route,method,code` | Description                      |
| ----------------------------- | ------- | -------------------------- | -------------------------------- |
| `openport_api_requests_total` | Counter | route, method, HTTP code   | Requests to admin/API endpoints. |

> **Tip (alerts):**
>
> * Exporter down: `up{job="openport_exporter"} == 0`
> * Backpressure: `increase(openport_scheduler_enqueue_failed_total[5m]) > 0`
> * p95 slow scans: `histogram_quantile(0.95, sum(rate(openport_scan_duration_seconds_bucket[10m])) by (le)) > 60`
> * Exposure changed: `increase(openport_port_state_changes_total[15m]) > 0`
> * Critical port closed (with background details): `openport_port_open{alias="ssh-bastion-primary",port="22"} == 0`

---

## Prometheus Integration

### Scrape config

```yaml
scrape_configs:
  - job_name: 'openport_exporter'
    metrics_path: /metrics
    static_configs:
      - targets: ['openport-exporter:9919']
```

> For Kubernetes, prefer a Service + ServiceMonitor and keep the exporter behind a NetworkPolicy that restricts egress to intended CIDRs.

---

## Security & Hardening

* **Least privilege**

  * SYN scans (`use_syn_scan: true`) require `CAP_NET_RAW`. Run the container **as non‑root** with **only** `NET_RAW`.
  * With `use_syn_scan: false`, no special capability is needed.
* **Network policy**

  * Enforce **egress** policies limiting scan destinations to the intended CIDRs.
* **Transport**

  * Expose behind TLS‑terminating ingress/proxy as needed.
* **Auth**

  * Tasks API supports **Bearer** and/or **Basic**. Prefer **Bearer**.
* **Trusted proxies & client allowlist**

  * Set `server.trusted_proxies_cidrs` to the networks of proxies allowed to supply `X-Forwarded-For`.
  * The exporter **only** trusts `X‑Forwarded‑For` if the direct client is **loopback/unspecified** or **within** `trusted_proxies_cidrs`.
  * Apply `policy.client_allow_cidrs` to restrict who can reach the Tasks API.
* **Rate limiting**

  * `policy.rate_limit_rps` + `rate_burst` apply globally and per‑IP to the Tasks API.
* **Task retention (GC)**

  * Control with `scheduler.task_gc_max` and `scheduler.task_gc_max_age`. Runs every 5 minutes.
* **Supply chain**

  * Pin dependencies; run `govulncheck`, `staticcheck`, `gosec` in CI.

---

## Operational Guidance

### Performance tips

* Start with defaults. Increase `min_rate` / `min_parallelism` gradually; cap with `max_rate`.
* Keep background `worker_count` modest; Nmap dominates I/O.
* `disable_host_discovery: true` (like `-Pn`) speeds scans when you’re confident hosts are up.
* Prefer narrower `port_range` for large CIDRs.

### Troubleshooting

* **Permission errors** with SYN → grant `CAP_NET_RAW` (or use `connect()` scans).
* **Slow scans** → narrow port ranges; tune `min_rate`, `max_retries`, `host_timeout`.
* **Config reload failed** → check file permissions/YAML; invalid configs are rejected and the current config remains active.
* **“Queue full” (429)** → increase `scheduler.task_queue_size`, reduce fan‑out (`max_cidr_size`), or provision more workers; for API, consider priorities and `max_concurrent`.

---

## Development

```bash
# Build & run
go build ./...
./openport-exporter --log.level=debug

# Tests (race + coverage)
go test -race -v ./...

# Formatting
go fmt ./...
```

---

## License

Licensed under the [MIT](./LICENSE).
