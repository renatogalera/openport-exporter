# OpenPort Exporter Documentation

OpenPort Exporter is an nmap-based tool that scans a list of IP addresses and ports and exposes the results as Prometheus metrics. It supports both TCP and UDP scans and provides detailed metrics to monitor your network's security posture.

## Configuration Options

The table below outlines all configurable options available in `config.yaml` for OpenPort Exporter.

| Option                            | Description                                                                  | Default Value | Type   |
|-----------------------------------|------------------------------------------------------------------------------|---------------|--------|
| `server.port`                     | Port to listen on                                                            | `9919`        | Int    |
| `scanning.interval`               | Interval between scans in seconds                                            | `86400`       | Int    |
| `scanning.port_range`             | Range of ports to scan                                                       | `"1-65535"`   | String |
| `scanning.max_cidr_size`          | Maximum CIDR size for splitting scans                                        | `24`          | Int    |
| `scanning.timeout`                | Timeout for each scan in seconds                                             | `3600`        | Int    |
| `scanning.duration_metrics`       | Enable/disable scan duration metrics                                         | `false`       | Bool   |
| `scanning.disable_dns_resolution` | Disable DNS resolution during scans                                          | `true`        | Bool   |
| `scanning.min_rate`               | Minimum packet rate per second for Nmap                                      | `1000`        | Int    |
| `scanning.min_parallelism`        | Minimum level of parallelism for Nmap                                        | `1000`        | Int    |
| `scanning.udp_scan`               | Enable UDP scanning along with TCP scanning                                  | `false`       | Bool   |
| `performance.rate_limit`          | Maximum number of API requests per minute                                    | `30`          | Int    |
| `performance.task_queue_size`     | Number of tasks that can be queued at once                                   | `1000`        | Int    |
| `performance.worker_count`        | Number of concurrent workers                                                 | `10`          | Int    |
| `auth.basic.username`             | Username for basic authentication                                            | `admin`       | String |
| `auth.basic.password`             | Password for basic authentication                                            | `secret`      | String |
| `targets`                         | List of IP ranges to scan                                                    | `- 192.168.10.1/32` | List   |

## Endpoints

The following HTTP endpoints are available for managing scans and retrieving metrics:

| Endpoint   | Method | Description                                                                 |
|------------|--------|-----------------------------------------------------------------------------|
| `/query`   | `GET`  | Triggers a new scan based on query parameters (`ip`, `ports`).              |
| `/metrics` | `GET`  | Provides Prometheus metrics about the scanning process.                     |
| `/healthz` | `GET`  | Provides health information about the service and the current task queue size. |

---

## Metrics

| Metric Name                         | Description                                                                                                          | Example                                                                                                        | Type      |
|-------------------------------------|----------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|-----------|
| `open_port_status`                  | Indicates that a specific port is open for a given IP address and protocol.                                          | `open_port_status{ip="127.0.0.1", port="443", protocol="tcp"} 1`                                               | Gauge     |
| `open_ports_total`                  | Total number of open ports for a given IP address.                                                                   | `open_ports_total{ip="127.0.0.1"} 5`                                                                             | Gauge     |
| `scan_duration_seconds`             | Duration of the last scan in seconds for the specified target, port range, and protocol (if enabled).                 | `scan_duration_seconds{target="127.0.0.1/32", port_range="1-65535", protocol="tcp"} 13.79`                       | Gauge     |
| `scan_duration_histogram_seconds`   | Histogram of scan durations in seconds, providing a distribution of scan times.                                      | `scan_duration_histogram_seconds_bucket{target="127.0.0.1/32", port_range="1-65535", protocol="tcp", le="1"} 3`    | Histogram |
| `task_queue_size`                   | The current number of tasks waiting in the scan queue.                                                               | `task_queue_size 5`                                                                                            | Gauge     |
| `nmap_scan_timeouts_total`          | Total number of Nmap scans that resulted in a timeout for a specific target, port range, and protocol.                 | `nmap_scan_timeouts_total{target="179.190.33.0/24", port_range="1-65535", protocol="tcp"} 1`                     | Counter   |
| `nmap_host_up_count`                | Number of hosts found up during the last scan for a given target.                                                    | `nmap_host_up_count{target="192.168.1.0/24"} 10`                                                                | Gauge     |
| `nmap_host_down_count`              | Number of hosts found down (unreachable) during the last scan for a given target.                                    | `nmap_host_down_count{target="192.168.1.0/24"} 5`                                                               | Gauge     |
| `scans_successful_total`            | Total number of scans completed without error for a given target, port range, and protocol.                          | `scans_successful_total{target="192.168.1.0/24", port_range="22-80", protocol="tcp"} 3`                           | Counter   |
| `scans_failed_total`                | Total number of scans that encountered an error for a given target, port range, and protocol, categorized by error type.| `scans_failed_total{target="192.168.1.0/24", port_range="22-80", protocol="tcp", error_type="timeout"} 1`         | Counter   |
| `last_scan_timestamp_seconds`       | Unix timestamp of the last completed scan for a given target, port range, and protocol.                              | `last_scan_timestamp_seconds{target="192.168.1.0/24", port_range="22-80", protocol="tcp"} 1695051127`              | Gauge     |
| `port_state_changes_total`          | Total number of port state changes (open->closed or closed->open) detected between scans for a given target.           | `port_state_changes_total{target="192.168.1.0/24", change_type="closed_to_open"} 2`                               | Counter   |

### Detailed Metric Descriptions

- **`open_port_status`**  
  - **Description**: Indicates that a specific port is open for the given IP address and protocol. A value of `1` means open, and `0` means closed.  
  - **Example**: `open_port_status{ip="127.0.0.1", port="443", protocol="tcp"} 1`  
  - **Type**: Gauge  

- **`open_ports_total`**  
  - **Description**: Aggregates the total number of open ports detected on a given IP address during the last scan.  
  - **Example**: `open_ports_total{ip="127.0.0.1"} 5`  
  - **Type**: Gauge  

- **`scan_duration_seconds`**  
  - **Description**: Records the duration of the last scan in seconds for the specified target, port range, and protocol. This is a snapshot value.  
  - **Example**: `scan_duration_seconds{target="127.0.0.1/32", port_range="1-65535", protocol="tcp"} 13.79`  
  - **Type**: Gauge  

- **`scan_duration_histogram_seconds`**  
  - **Description**: Provides a histogram of scan durations, offering a distribution of how long scans are taking over time. Useful for performance analysis and identifying outliers.  
  - **Example**: `scan_duration_histogram_seconds_bucket{target="127.0.0.1/32", port_range="1-65535", protocol="tcp", le="1"} 3`  
  - **Type**: Histogram  

- **`task_queue_size`**  
  - **Description**: Shows the current number of tasks waiting in the scan queue.  
  - **Example**: `task_queue_size 5`  
  - **Type**: Gauge  

- **`nmap_scan_timeouts_total`**  
  - **Description**: Counts how many Nmap scans have timed out, indicating potential performance or connectivity issues.  
  - **Example**: `nmap_scan_timeouts_total{target="179.190.33.0/24", port_range="1-65535", protocol="tcp"} 1`  
  - **Type**: Counter  

- **`nmap_host_up_count`**  
  - **Description**: Reflects the number of hosts that were up during the last scan for a target, indicating network reachability.  
  - **Example**: `nmap_host_up_count{target="192.168.1.0/24"} 10`  
  - **Type**: Gauge  

- **`nmap_host_down_count`**  
  - **Description**: Indicates the number of hosts that were down (unreachable) during the last scan for a target.  
  - **Example**: `nmap_host_down_count{target="192.168.1.0/24"} 5`  
  - **Type**: Gauge  

- **`scans_successful_total`**  
  - **Description**: Counts the total number of scans that completed successfully without errors for a particular target, port range, and protocol.  
  - **Example**: `scans_successful_total{target="192.168.1.0/24", port_range="22-80", protocol="tcp"} 3`  
  - **Type**: Counter  

- **`scans_failed_total`**  
  - **Description**: Counts the total number of scans that encountered errors, with an additional label (`error_type`) that categorizes the type of error (e.g., timeout, permission, other).  
  - **Example**: `scans_failed_total{target="192.168.1.0/24", port_range="22-80", protocol="tcp", error_type="timeout"} 1`  
  - **Type**: Counter  

- **`last_scan_timestamp_seconds`**  
  - **Description**: Provides the Unix timestamp of the most recent scan for a given target, port range, and protocol.  
  - **Example**: `last_scan_timestamp_seconds{target="192.168.1.0/24", port_range="22-80", protocol="tcp"} 1695051127`  
  - **Type**: Gauge  

- **`port_state_changes_total`**  
  - **Description**: Tracks the number of port state changes detected between scans for a target. This metric can alert you to sudden changes in network exposure (e.g., ports that have unexpectedly opened or closed).  
  - **Example**: `port_state_changes_total{target="192.168.1.0/24", change_type="closed_to_open"} 2`  
  - **Type**: Counter  

---

### Monitoring and Alerting Recommendations

- **Set Thresholds**:  
  Define acceptable ranges for metrics such as `open_ports_total` and `port_state_changes_total` per IP, and configure alerts if these thresholds are exceeded.

- **Track Changes Over Time**:  
  Utilize both snapshot and histogram metrics (`scan_duration_seconds` and `scan_duration_histogram_seconds`) to monitor performance trends and detect anomalies.

- **Combine Metrics**:  
  Use `open_port_status` for detailed analysis of specific open ports and `open_ports_total` for an aggregated view of network exposure.

- **Error Categorization**:  
  Leverage the `scans_failed_total` metric with the `error_type` label to identify recurring issues (e.g., timeouts or permission errors) and address underlying problems.

---

### Prometheus Query Examples

- **Total Open Ports Across All IPs**:
  
  ```promql
  sum(open_ports_total)
  ```

- **List IPs with More Than 10 Open Ports**:

  ```promql
  open_ports_total > 10
  ```
  
- **Detect Sudden Increase in Open Ports (over the last hour)**:

  ```promql
  increase(open_ports_total[1h]) > 5
  ```

- **Find Specific Open Ports on an IP**:
  
  ```promql
  open_port_status{ip="192.168.1.100"} == 1
  ```

- **Analyze Scan Duration Distribution**:

  ```promql
  histogram_quantile(0.95, sum(rate(scan_duration_histogram_seconds_bucket[5m])) by (le, target))
  ```

- **Monitor Port State Changes**:

  ```promql
  rate(port_state_changes_total[5m])
  ```

---

### Additional Notes

- **Data Retention**:  
  Be mindful of Prometheus data retention settings, especially when dealing with high-cardinality metrics such as `open_port_status`.

- **Performance Considerations**:  
  Monitor Prometheus performance and adjust scraping intervals or metric granularity as needed.

- **Security**:  
  Ensure that access to the `/metrics` endpoint is secured to prevent exposure of sensitive network information.

- **UDP Scanning**:  
  When enabled (`scanning.udp_scan: true`), UDP scanning is performed alongside TCP scanning. This provides a more comprehensive view of network exposure, though it may increase scan duration and resource usage.

---

## Configuration

Below is an example `config.yaml` file that demonstrates how to configure OpenPort Exporter with the new metrics and UDP scanning support:

```yaml
# Server configuration
server:
  port: 9919 # Port to listen on (default: 9919)

# Scanning configuration  
scanning:
  interval: 86400           # Interval between scans in seconds (default: 86400)
  port_range: "1-65535"      # Port range to scan
  max_cidr_size: 24         # Maximum CIDR size for splitting scans
  timeout: 3600             # Timeout for each scan in seconds
  duration_metrics: false   # Enable scan duration metric
  disable_dns_resolution: true
  min_rate: 1000            # Minimum packet rate per second for Nmap
  min_parallelism: 1000     # Minimum parallelism for Nmap
  udp_scan: false           # Enable UDP scanning (default: false)

# Performance configuration
performance:
  rate_limit: 30            # Request limit per minute
  task_queue_size: 1000     # Size of the task queue
  worker_count: 10          # Number of concurrent workers 

# Authentication (if omitted, the exporter will be public)
auth:
  basic:
    username: admin
    password: secret

# Targets 
targets:
  - 192.168.10.1/32
```

---

## Example Usage

**Triggering a Scan:**

```bash
curl "http://localhost:9919/query?ip=192.168.1.0/24&ports=22-80"
```

**Retrieving Metrics:**

```bash
curl "http://localhost:9919/metrics"
```

---

## Prometheus Usage

After starting OpenPort Exporter, configure Prometheus to scrape the `/metrics` endpoint:

```yaml
scrape_configs:
  - job_name: 'openport_exporter'
    static_configs:
      - targets: ['localhost:9919']
```

---

## Development and Testing

**Running the Service:**

```bash
sudo go run main.go
```

**Running Tests:**

```bash
go test -v ./...
```

---