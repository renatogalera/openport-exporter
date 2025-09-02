# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## Unreleased

### Added
- Adopt Prometheus exporter boilerplate structure: `cmd/`, `internal/{collectors,httpserver,sloglogger,config,metrics,scanner}`.
- CLI with Cobra/Viper: flags for logging, metrics path, listen port, config path, and optional collectors.
- Optional standard collectors: `build_info` and `go_*` (controlled via flags/env).

### Changed
- Canonicalize metric names under namespace `openport_`:
  - `openport_port_open` (gauge, per ip/port/protocol)
  - `openport_ports_open` (gauge, open ports per IP)
  - `openport_last_scan_duration_seconds` (gauge)
  - `openport_scan_duration_seconds` (histogram)
  - `openport_task_queue_size` (gauge)
  - `openport_nmap_scan_timeouts_total` (counter)
  - `openport_nmap_host_up_count` / `openport_nmap_host_down_count` (gauges)
  - `openport_scans_successful_total` / `openport_scans_failed_total` (counters)
  - `openport_last_scan_timestamp_seconds` (gauge)
  - `openport_port_state_changes_total` (counter)

### Removed
- Non-standard HTTP endpoints `/query` and `/healthz`. Exporter now exposes only `/` and `/metrics`.
- Legacy `app/`, `healthcheck/`, and `middleware/` packages.
