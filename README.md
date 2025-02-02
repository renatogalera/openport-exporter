# OpenPort Exporter Documentation

OpenPort Exporter is an nmap-based tool that scans a list of IP addresses and ports and exposes the results as Prometheus metrics.

## Configuration Options

The table below outlines all configurable options available in `config.yaml` for OpenPort Exporter.

| Option                         | Description                                                                 | Default Value | Type   |
|---------------------------------|-----------------------------------------------------------------------------|---------------|--------|
| `server.port`                   | Port to listen on                                                            | `9919`        | Int    |
| `scanning.interval`             | Interval between scans in seconds                                            | `86400`       | Int    |
| `scanning.port_range`           | Range of ports to scan                                                        | `"1-65535"`   | String |
| `scanning.max_cidr_size`        | Maximum CIDR size for splitting scans                                        | `24`          | Int    |
| `scanning.timeout`              | Timeout for each scan in seconds                                             | `3600`        | Int    |
| `scanning.duration_metrics`     | Enable/disable scan duration metrics                                         | `false`       | Bool   |
| `scanning.disable_dns_resolution` | Disable DNS resolution during scans                                        | `true`        | Bool   |
| `scanning.min_rate`             | Minimum packet rate per second for Nmap                                      | `1000`        | Int    |
| `scanning.min_parallelism`      | Minimum level of parallelism for Nmap                                        | `1000`        | Int    |
| `performance.rate_limit`        | Maximum number of API requests per minute                                    | `30`          | Int    |
| `performance.task_queue_size`   | Number of tasks that can be queued at once                                   | `1000`        | Int    |
| `performance.worker_count`      | Number of concurrent workers                                                  | `10`          | Int    |
| `auth.basic.username`           | Username for basic authentication                                            | `admin`       | String |
| `auth.basic.password`           | Password for basic authentication                                            | `secret`      | String |
| `targets`                       | List of IP ranges to scan                                                    | `- 192.168.10.1/32` | List   |

## Endpoints

The following HTTP endpoints are available for managing scans and retrieving metrics:

| Endpoint   | Method | Description                                                                 |
|------------|--------|-----------------------------------------------------------------------------|
| `/query`   | `GET`  | Triggers a new scan based on query params (`ip`, `ports`).                  |
| `/metrics` | `GET`  | Provides Prometheus metrics about the scanning process.                     |
| `/healthz` | `GET`  | Provides health information about the service and queue size.               |

---

## Metrics

| Metric Name                | Description                                                                                              | Example                                                                                                   | Type    |
|----------------------------|----------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|---------|
| `open_port_status`                | Indicates that a specific port is open for a given IP address and protocol                               | `open_port_status{ip="127.0.0.1", port="443", protocol="tcp"} 1`                                                 | Gauge   |
| `open_ports_total`         | Total number of open ports for a given IP address                                                        | `open_ports_total{ip="127.0.0.1"} 5`                                                                      | Gauge   |
| `scan_duration_seconds`    | Duration of the last scan in seconds for the specified target, port range, and protocol (if enabled)      | `scan_duration_seconds{target="127.0.0.1/32", port_range="1-65535", protocol="tcp"} 13.79`                | Gauge   |
| `task_queue_size`          | The current number of tasks waiting in the scan queue                                                    | `task_queue_size 5`                                                                                       | Gauge   |
| `nmap_scan_timeouts_total` | Total number of Nmap scans that resulted in a timeout for a specific target, port range, and protocol    | `nmap_scan_timeouts_total{target="179.190.33.0/24", port_range="1-65535", protocol="tcp"} 1`              | Counter |

### Detailed Metric Descriptions

- **`open_port_status`**
  - **Description**: Indicates that a specific port is open for the given IP address and protocol. The value is `1` when the port is detected as open and `0` when closed.
  - **Example**: `open_port_status{ip="127.0.0.1", port="443", protocol="tcp"} 1`
  - **Type**: Gauge

- **`open_ports_total`**
  - **Description**: Represents the total number of open ports for a given IP address. This metric helps in monitoring the overall exposure of services on a specific IP.
  - **Example**: `open_ports_total{ip="127.0.0.1"} 5`
  - **Type**: Gauge

- **`scan_duration_seconds`**
  - **Description**: Records the duration of the last scan in seconds for the specified target, port range, and protocol. This metric appears only if scan duration tracking is enabled.
  - **Example**: `scan_duration_seconds{target="127.0.0.1/32", port_range="1-65535", protocol="tcp"} 13.79`
  - **Type**: Gauge

- **`task_queue_size`**
  - **Description**: Represents the current size of the task queue, showing how many tasks are awaiting processing. It reflects the queue's load in real-time.
  - **Example**: `task_queue_size 5`
  - **Type**: Gauge

- **`nmap_scan_timeouts_total`**
  - **Description**: Counts the total number of Nmap scans that resulted in a timeout for a specific target, port range, and protocol. This helps monitor performance issues or scan availability.
  - **Example**: `nmap_scan_timeouts_total{target="179.190.33.0/24", port_range="1-65535", protocol="tcp"} 1`
  - **Type**: Counter

---

### Explanation of the New Metric `open_ports_total`

- **Metric Name**: `open_ports_total`
- **Type**: Gauge
- **Labels**:
  - `ip`: The IP address for which the total number of open ports is reported.

#### **Description**

The `open_ports_total` metric provides the total count of open ports detected on a specific IP address during the last scan. This metric aggregates the number of open ports, allowing you to monitor changes in the exposure level of each IP over time.

#### **Usage**

- **Monitoring Exposure**: Track the number of open ports on critical IPs to detect unexpected increases, which may indicate security vulnerabilities or unauthorized services.
- **Anomaly Detection**: Set up alerts if the number of open ports exceeds a predefined threshold.
- **Trend Analysis**: Observe trends in the number of open ports to plan for capacity or security measures.

#### **Example**

If an IP address `192.168.1.100` has 5 open ports detected in the latest scan, the metric would be reported as:

open_ports_total{ip="192.168.1.100"} 5

#### **Important Notes**

- **Dynamic Updates**: The metric updates with each scan, reflecting the current state of open ports for each IP.
- **Zero Values**: If an IP had open ports in previous scans but none in the current scan, `open_ports_total` will report `0` for that IP.
- **Label Cardinality**: Be cautious of high cardinality if scanning a large number of IPs. Monitor Prometheus performance and consider grouping IPs if necessary.

---

### Combining with Existing Metrics

By using both `open_port_status` and `open_ports_total`, you can achieve a comprehensive monitoring setup:

- **`open_port_status`**: Allows you to see which specific ports are open on each IP. Useful for detailed inspections and identifying exact services that are exposed.
- **`open_ports_total`**: Provides a high-level view of the total number of open ports per IP, which is helpful for detecting general exposure levels and trends.

#### **Example Scenario**

Suppose you notice that `open_ports_total{ip="192.168.1.100"}` has increased from `5` to `10` in the last scan. You can then investigate further by examining the `open_port_status` metrics to identify which new ports have opened:

open_port_status{ip="192.168.1.100", port="22", protocol="tcp"} 1
open_port_status{ip="192.168.1.100", port="80", protocol="tcp"} 1
open_port_status{ip="192.168.1.100", port="443", protocol="tcp"} 1
...

### Monitoring and Alerting Recommendations

- **Set Thresholds**: Define acceptable ranges for `open_ports_total` per IP and configure alerts if thresholds are exceeded.
- **Track Changes Over Time**: Use Prometheus queries to monitor increases or decreases in `open_ports_total` to detect anomalies.
- **Combine Metrics**: Utilize `open_ports_total` for high-level monitoring and `open_port_status` for detailed analysis when alerts are triggered.

---

### Prometheus Query Examples

- **Total Open Ports Across All IPs**:
  
  sum(open_ports_total)

- **List IPs with More Than 10 Open Ports**:

  open_ports_total > 10
  
- **Detect Sudden Increase in Open Ports (over the last hour)**:

  increase(open_ports_total[1h]) > 5

- **Find Specific Open Ports on an IP**:
  
  open_port_status{ip="192.168.1.100"} == 1

---

### Additional Notes

- **Data Retention**: Be mindful of the data retention settings in Prometheus, especially if scanning a large number of IPs and ports.
- **Performance Considerations**: Monitor Prometheus performance due to the potential high cardinality from the `open_port_status` metric. If necessary, optimize your monitoring strategy to balance detail and performance.
- **Security**: Ensure that access to these metrics is appropriately secured, as they may reveal sensitive network information.

## Configuration

The `config.yaml` file allows you to customize the behavior of OpenPort Exporter. Below are the key configuration options:

```yaml
# Server configuration
server:
  port: 9919 # Port to listen on (default: 9919)

# Scanning configuration  
scanning:
  interval: 86400 # Interval between scans in seconds (default: 10800)
  port_range: "1-65535" # Port range to scan
  max_cidr_size: 24 # Maximum CIDR size for splitting scans
  timeout: 3600 # Timeout for each scan in seconds
  duration_metrics: false # Enable scan duration metric
  disable_dns_resolution: true
  min_rate: 1000 # Minimum packet rate per second for Nmap
  min_parallelism: 1000   # Minimum parallelism for Nmap

# Performance configuration
performance:
  rate_limit: 30 # Request limit per minute
  task_queue_size: 1000   # Size of the task queue
  worker_count: 10 # Number of concurrent workers 

# Authentication, if commented, the exporter will be public
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

**Getting Metrics:**

```bash
curl "http://localhost:9919/metrics"
```

---

## Prometheus Usage

Start the OpenPort Exporter and access the `/metrics` endpoint to view the exposed metrics. You can configure Prometheus to collect these metrics and create alerts based on them.

### Prometheus Configuration Example

Add the following scrape configuration to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'openport_exporter'
    static_configs:
      - targets: ['localhost:9919']
```

### Development and Testing

**Running the Service:**

```bash
sudo go run main.go
```

**Running Tests:**

```bash
go test -v ./...
```

---
