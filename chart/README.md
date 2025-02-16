# OpenPort Exporter Helm Chart

This repository contains the **OpenPort Exporter Helm Chart**, which packages and simplifies the deployment of the [OpenPort Exporter](https://github.com/renatogalera/openport-exporter) in a Kubernetes cluster.
It provides functionality for monitoring and collecting metrics about open ports, helping detect potential security vulnerabilities or unexpected network behavior.

---

## Overview

**OpenPort Exporter** periodically scans ports based on configurable intervals, exposing Prometheus metrics about the status of each scanned port. This Helm Chart seamlessly integrates into the Kubernetes ecosystem, offering:

- Manifest files for **Deployment**, **Service**, **ConfigMap**, **Ingress**, **PodDisruptionBudget**, and **ServiceMonitor** (for Prometheus Operator).
- Optional Basic Auth integration.
- Mechanisms to adjust tolerations, affinities, pod security context, and container security context.
- Configurable resources, replica counts, and **advanced Nmap performance tuning options** for optimization.

---

## Repository Structure

```plaintext
openport-exporter/
├── Chart.yaml
├── templates
│   ├── configmap.yaml
│   ├── deployment.yaml
│   ├── _helpers.tpl
│   ├── ingress.yaml
│   ├── pdb.yaml
│   ├── servicemonitor.yaml
│   └── service.yaml
└── values.yaml
```

- **Chart.yaml**: Chart metadata (name, version, description, maintainers, etc.).
- **templates/**: Directory containing Kubernetes object templates that Helm will render.
- **values.yaml**: Default configuration values that can be overridden by the user during installation or upgrade.

---

## Prerequisites

1. Kubernetes **1.19** or later
2. Helm **v3** or later
3. (Optional) Prometheus Operator installed, if you want to use the **ServiceMonitor**

---

## Installation

1. **Add** the chart repository (example placeholder in case you publish your chart to a personal Helm repo):

   ```bash
   helm repo add openport-repo https://example.com/openport-exporter
   helm repo update
   ```

2. **Install** the chart:

   ```bash
   helm install my-openport-exporter openport-repo/openport-exporter
   ```

   To customize values, use the `--values` or `-f` flag:

   ```bash
   helm install my-openport-exporter openport-repo/openport-exporter -f custom-values.yaml
   ```

3. Wait for resource creation, then check if everything is running:

   ```bash
   kubectl get pods,svc,deploy -l app.kubernetes.io/name=openport-exporter
   ```

   After installation, Helm will output a **NOTES.txt** with helpful instructions, including how to access your OpenPort Exporter and important security reminders. **Please refer to the NOTES.txt output after installation for crucial post-installation steps.**

---

## Upgrading

To upgrade the **OpenPort Exporter** version or modify parameters:

```bash
helm upgrade my-openport-exporter openport-repo/openport-exporter -f custom-values.yaml
```

---

## Uninstallation

Remove all resources created by the chart:

```bash
helm uninstall my-openport-exporter
```

---

## Configuration

All configuration can be adjusted in **values.yaml** or overridden in an external file. Below are some important parameters:

| Parameter                                       | Description                                                                                        | Default                          |
|-------------------------------------------------|----------------------------------------------------------------------------------------------------|----------------------------------|
| `image.repository`                              | Docker image repository path                                                                       | `renatogalera/openport-exporter` |
| `image.tag`                                     | Docker image tag                                                                                   | `v0.1.0`                         |
| `image.pullPolicy`                              | Docker image pull policy                                                                           | `IfNotPresent`                   |
| `replicaCount`                                  | Number of replicas for the Deployment                                                             | `1`                              |
| `basicAuth.enabled`                             | Enable basic authentication                                                                        | `false`                          |
| `service.type`                                  | Service type (ClusterIP, NodePort, LoadBalancer)                                                  | `ClusterIP`                      |
| `service.port`                                  | Service port to expose metrics                                                                     | `9919`                           |
| `config.server.port`                            | Internal server port used by the Exporter                                                          | `9919`                           |
| `config.scanning.interval`                      | Interval (in seconds) between port scans                                                           | `86400`                          |
| `config.scanning.port_range`                    | Port range to be scanned                                                                          | `1-65535`                        |
| `config.scanning.timeout`                       | Timeout (in seconds) for each scan                                                                 | `10800`                          |
| `config.scanning.min_rate`                      | Minimum packet rate per second for Nmap                                                                     | `1000`                          |
| `config.scanning.max_rate`                      | Maximum packet rate per second for Nmap (0 for unlimited)                                                  | `0`                             |
| `config.scanning.min_parallelism`               | Minimum level of parallelism for Nmap                                                                       | `1000`                          |
| `config.scanning.max_retries`                   | Maximum port scan probe retransmissions by Nmap                                                            | `6`                             |
| `config.scanning.host_timeout`                  | Give up on target after this many seconds                                                                    | `300` (5 mins)                 |
| `config.scanning.scan_delay`                    | Delay between probes in milliseconds                                                                        | `0`                             |
| `config.scanning.max_scan_delay`                | Maximum delay to adjust to in milliseconds                                                                  | `0`                             |
| `config.scanning.initial_rtt_timeout`           | Initial RTT timeout in milliseconds                                                                         | `0`                             |
| `config.scanning.max_rtt_timeout`               | Maximum RTT timeout in milliseconds                                                                         | `0`                             |
| `config.scanning.min_rtt_timeout`               | Minimum RTT timeout in milliseconds                                                                         | `0`                             |
| `config.scanning.disable_host_discovery`        | Disable Nmap host discovery (-Pn option), assuming all hosts are up                                          | `true`                          |
| `readinessProbe.enabled`, `livenessProbe.enabled` | Enable or disable container health probes                                                         | `true`                           |
| `serviceMonitor.enabled`                        | Enable ServiceMonitor (requires Prometheus Operator)                                              | `false`                          |
| `podDisruptionBudget.enabled`                   | Enable PodDisruptionBudget                                                                        | `false`                          |
| `ingress.enabled`                               | Enable an Ingress resource to expose the service externally                                        | `false`                          |

For a comprehensive list of configurable parameters, please refer to the [values.yaml](./values.yaml) file and the detailed descriptions within.

---

## Performance Tuning with Nmap Options Configuration

OpenPort Exporter leverages Nmap's powerful scanning engine, and this Helm chart exposes several options to fine-tune scan performance directly through `values.yaml`. These settings, located under `config.scanning` in the `values.yaml`, allow you to optimize scan speed and resource usage according to your specific network environment and monitoring requirements.

**It is highly recommended to benchmark and profile your OpenPort Exporter deployment after adjusting these parameters to ensure you are achieving the desired performance gains without compromising scan accuracy.**

Here's a breakdown of the Nmap performance tuning options available:

- **`config.scanning.min_rate`**:  Sets the minimum number of packets to send per second to the target.  Increasing this value can significantly speed up scans, especially on fast, reliable networks. However, be cautious as excessively high rates might lead to inaccurate results due to packet loss or be flagged as suspicious network activity by intrusion detection systems.

- **`config.scanning.max_rate`**:  Sets the maximum number of packets to send per second. Use this to cap the scan rate, preventing network congestion or reducing the likelihood of detection. Setting this to `0` (default) effectively disables the maximum rate limit, and the scan rate will only be bounded by `min_rate`.

- **`config.scanning.min_parallelism`**:  Controls the minimum number of probes Nmap sends in parallel for port scanning. Increasing parallelism can substantially speed up scans, especially when scanning a large number of ports or hosts. Experiment to find the optimal value for your network.

- **`config.scanning.max_retries`**:  Determines the maximum number of port scan probe retransmissions Nmap will attempt. Lowering this value can accelerate scans in highly reliable networks with minimal packet loss. Conversely, in less reliable network environments, decreasing retries too much might lead to missed open ports.

- **`config.scanning.host_timeout`**:  Specifies the maximum time in seconds Nmap will spend scanning a single host before giving up. Reducing this timeout will instruct Nmap to skip hosts that are slow to respond or are down, thus speeding up the overall scan, particularly across large networks where many hosts might be inactive.

- **`config.scanning.scan_delay`**:  Sets a minimum delay in milliseconds between probes sent to *each host*. Increasing this delay makes scans slower and less aggressive, potentially useful for avoiding detection by intrusion prevention systems or rate limiting on target networks.

- **`config.scanning.max_scan_delay`**:  Defines the maximum scan delay in milliseconds that Nmap will dynamically adjust to during runtime to maintain optimal performance.

- **`config.scanning.initial_rtt_timeout`**:  Configures the initial round-trip time timeout, in milliseconds, for probes.  In networks with low latency, lowering this initial timeout can lead to faster scans.

- **`config.scanning.max_rtt_timeout`**:  Sets the maximum round-trip time timeout, in milliseconds. Nmap will not wait longer than this for a response to a probe.

- **`config.scanning.min_rtt_timeout`**:  Specifies the minimum round-trip time timeout, in milliseconds. Nmap will attempt to probe quickly, down to this timeout value, if network conditions allow.

- **`config.scanning.disable_host_discovery`**:  When set to `true`, this option directly translates to Nmap's `-Pn` command-line flag. It completely disables the host discovery phase of Nmap and assumes that all target hosts are online and responsive. This can provide a significant speed boost, especially when scanning large IP ranges where you are confident that most hosts are up. **However, exercise caution when enabling this option, as scanning non-existent or offline hosts will still consume scanning resources and time, potentially without yielding useful results.**

To configure these options, modify the `config` section within your `values.yaml` file, as shown in the example below. Remember to test and adjust these values incrementally to find the best balance of speed and accuracy for your specific use case.

---

## Ingress

If you want to expose the **OpenPort Exporter** externally via Ingress, enable the `ingress` section:

```yaml
ingress:
  enabled: true
  className: "nginx"
  host: "openport.example.com"
  annotations: {}
  tls: []
  # Example: Enable TLS (HTTPS)
  # tls:
  #   - hosts:
  #     - "openport.example.com"
  #     secretName: "openport-tls-cert"
```

This will create an Ingress object routing HTTP/HTTPS traffic to the Exporter’s service.  To enable HTTPS, configure the `tls` section with your host and secret name containing the TLS certificate.

---

## ServiceMonitor

To integrate with **Prometheus Operator**, enable the `serviceMonitor`:

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
  labels: {}
  annotations: {}
  namespace: "" # Optionally specify a namespace for ServiceMonitor (defaults to same namespace as exporter)
```

Once enabled, a **ServiceMonitor** object will be created in your cluster. Ensure that your Prometheus Operator is configured to watch the namespace where you deploy the OpenPort Exporter (or the namespace specified in `serviceMonitor.namespace`) so it can automatically discover the Exporter and begin scraping metrics.

---

## Basic Auth

You can configure basic authentication to secure the `/metrics` endpoint:

```yaml
basicAuth:
  enabled: true
  username: "admin"       # Change this to a strong username
  password: "your_strong_password_here" # **IMPORTANT: Change this to a strong, unique password!**
```

The chart will create a Kubernetes Secret named `<chart-fullname>-basic-auth` to store the provided username and password. These credentials will then be injected as environment variables into the OpenPort Exporter container.

**Security Warning:** **It is crucial to change the default password in the `basicAuth` section of your `values.yaml` before deploying to any non-testing environment.** Using default credentials poses a significant security risk. Choose a strong, unique password and manage access to your `values.yaml` and Kubernetes Secrets securely.

---

## Maintainers

- **Renato Guilhermini** – [rennato@gmail.com](mailto:rennato@gmail.com)

---

## License

This project is licensed under the [MIT](./LICENSE) license.

---

## References

- [OpenPort Exporter - Official Repository](https://github.com/renatogalera/openport-exporter)
- [Helm Documentation](https://helm.sh/docs/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)

---