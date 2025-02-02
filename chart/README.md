# OpenPort Exporter Helm Chart

This repository contains the **OpenPort Exporter Helm Chart**, which packages and simplifies the deployment of the [OpenPort Exporter](https://github.com/renatogalera/openport-exporter) in a Kubernetes cluster.  
It provides functionality for monitoring and collecting metrics about open ports, helping detect potential security vulnerabilities or unexpected network behavior.

---

## Overview

**OpenPort Exporter** periodically scans ports based on configurable intervals, exposing Prometheus metrics about the status of each scanned port. This Helm Chart seamlessly integrates into the Kubernetes ecosystem, offering:

- Manifest files for **Deployment**, **Service**, **ConfigMap**, **Ingress**, **PodDisruptionBudget**, and **ServiceMonitor** (for Prometheus Operator).  
- Optional Basic Auth integration.  
- Mechanisms to adjust tolerations, affinities, pod security context, and container security context.  
- Configurable resources and replica counts for performance optimization.  

---

## Repository Structure

```plaintext
openport-exporter/
├── Chart.yaml
├── templates
│   ├── configmap.yaml
│   ├── deployment.yaml
│   ├── _helpers.tpl
│   ├── ingress.yaml
│   ├── pdb.yaml
│   ├── servicemonitor.yaml
│   └── service.yaml
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
| `readinessProbe.enabled`, `livenessProbe.enabled` | Enable or disable container health probes                                                         | `true`                           |
| `serviceMonitor.enabled`                        | Enable ServiceMonitor (requires Prometheus Operator)                                              | `false`                          |
| `podDisruptionBudget.enabled`                   | Enable PodDisruptionBudget                                                                        | `false`                          |
| `ingress.enabled`                               | Enable an Ingress resource to expose the service externally                                        | `false`                          |

For more details, see the [values.yaml](./values.yaml) file.

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
```

This will create an Ingress object routing HTTP/HTTPS traffic to the Exporter’s service.

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
  namespace: ""
```

Once enabled, a **ServiceMonitor** object will be created, allowing the Prometheus Operator to automatically discover the Exporter and scrape metrics.

---

## Basic Auth

You can configure basic authentication to secure the `/metrics` endpoint:

```yaml
basicAuth:
  enabled: true
  username: "admin"
  password: "secret"
```

The chart will create a Kubernetes Secret to store the credentials and inject them as environment variables into the container.

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