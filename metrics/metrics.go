package metrics

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricsCollector encapsulates all Prometheus metrics.
type MetricsCollector struct {
	openPorts           *prometheus.GaugeVec
	openPortsTotal      *prometheus.GaugeVec
	scanDuration        *prometheus.GaugeVec
	taskQueueSizeMetric prometheus.Gauge
	scanTimeouts        *prometheus.CounterVec

	// New gauge to capture how many workers are busy at a given time.
	workerUtilization *prometheus.GaugeVec

	scannedTargets sync.Map
}

// NewMetricsCollector creates and initializes a new MetricsCollector.
func NewMetricsCollector() *MetricsCollector {
	mc := &MetricsCollector{
		openPorts: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "open_port_status",
				Help: "Open ports detected by SYN scan",
			},
			[]string{"ip", "port", "protocol"},
		),
		openPortsTotal: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "open_ports_total",
				Help: "Total number of open ports per IP",
			},
			[]string{"ip"},
		),
		scanDuration: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "scan_duration_seconds",
				Help: "Duration of the last port scan in seconds",
			},
			[]string{"target", "port_range", "protocol"},
		),
		taskQueueSizeMetric: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "task_queue_size",
				Help: "The current size of the task queue",
			},
		),
		scanTimeouts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nmap_scan_timeouts_total",
				Help: "Total number of Nmap scans that timed out",
			},
			[]string{"target", "port_range", "protocol"},
		),
		workerUtilization: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "worker_utilization",
				Help: "Number of currently busy workers out of the total worker pool",
			},
			[]string{"state"}, // e.g. state could be "busy"
		),
	}

	return mc
}

// Describe sends the super-set of all descriptors of metrics to the provided channel.
func (mc *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	mc.openPorts.Describe(ch)
	mc.openPortsTotal.Describe(ch)
	mc.scanDuration.Describe(ch)
	mc.taskQueueSizeMetric.Describe(ch)
	mc.scanTimeouts.Describe(ch)
	mc.workerUtilization.Describe(ch)
}

// Collect is called by the Prometheus registry when collecting metrics.
func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	mc.openPorts.Collect(ch)
	mc.openPortsTotal.Collect(ch)
	mc.scanDuration.Collect(ch)
	mc.taskQueueSizeMetric.Collect(ch)
	mc.scanTimeouts.Collect(ch)
	mc.workerUtilization.Collect(ch)
}

// ScanInfo holds information about a scan.
type ScanInfo struct {
	Ports    map[string]struct{}
	LastScan time.Time
}

// UpdateMetrics updates the metrics with new scan results.
func (mc *MetricsCollector) UpdateMetrics(targetKey string, newResults map[string]struct{}) {
	prevScanInfo := mc.getPreviousScanInfo(targetKey)

	mc.updateNewOpenPorts(newResults)
	mc.updateClosedPorts(prevScanInfo.Ports, newResults)
	mc.updateOpenPortsTotal(prevScanInfo.Ports, newResults)

	mc.storeCurrentScanInfo(targetKey, newResults)
}

// CanScan checks if a new scan can be performed based on the scan interval.
func (mc *MetricsCollector) CanScan(targetKey string, scanInterval time.Duration) bool {
	infoInterface, exists := mc.scannedTargets.Load(targetKey)
	if !exists {
		return true
	}
	info := infoInterface.(*ScanInfo)
	return time.Since(info.LastScan) >= scanInterval
}

// RegisterScan registers a new scan with the current time.
func (mc *MetricsCollector) RegisterScan(targetKey string) {
	mc.scannedTargets.Store(targetKey, &ScanInfo{
		Ports:    make(map[string]struct{}),
		LastScan: time.Now(),
	})
}

// IncrementScanTimeout increments the scan timeout counter.
func (mc *MetricsCollector) IncrementScanTimeout(target, portRange, protocol string) {
	mc.scanTimeouts.WithLabelValues(target, portRange, protocol).Inc()
}

// ObserveScanDuration sets the duration metric of a scan.
func (mc *MetricsCollector) ObserveScanDuration(target, portRange, protocol string, duration float64) {
	mc.scanDuration.WithLabelValues(target, portRange, protocol).Set(duration)
}

// UpdateTaskQueueSize updates the task queue size metric.
func (mc *MetricsCollector) UpdateTaskQueueSize(queueSize int) {
	mc.taskQueueSizeMetric.Set(float64(queueSize))
}

// UpdateWorkerUtilization sets the number of busy workers in the metric.
func (mc *MetricsCollector) UpdateWorkerUtilization(busy int) {
	// We track how many are busy at the moment
	mc.workerUtilization.WithLabelValues("busy").Set(float64(busy))
}

// ------------------- PRIVATE METHODS -------------------

func (mc *MetricsCollector) getPreviousScanInfo(targetKey string) *ScanInfo {
	prevScanInfoInterface, _ := mc.scannedTargets.Load(targetKey)
	if prevScanInfoInterface == nil {
		return &ScanInfo{Ports: make(map[string]struct{})}
	}
	return prevScanInfoInterface.(*ScanInfo)
}

func (mc *MetricsCollector) updateNewOpenPorts(newResults map[string]struct{}) {
	for portKey := range newResults {
		parts := strings.Split(portKey, ":")
		if len(parts) == 2 {
			ip := parts[0]
			port := parts[1]
			mc.openPorts.WithLabelValues(ip, port, "tcp").Set(1)
		}
	}
}

func (mc *MetricsCollector) updateClosedPorts(prevPorts, newResults map[string]struct{}) {
	for portKey := range prevPorts {
		if _, stillOpen := newResults[portKey]; !stillOpen {
			parts := strings.Split(portKey, ":")
			if len(parts) == 2 {
				ip := parts[0]
				port := parts[1]
				mc.openPorts.WithLabelValues(ip, port, "tcp").Set(0)
			}
		}
	}
}

func (mc *MetricsCollector) updateOpenPortsTotal(prevPorts, newPorts map[string]struct{}) {
	ipPortCount := make(map[string]int)

	// Count open ports for each IP in newPorts
	for portKey := range newPorts {
		parts := strings.Split(portKey, ":")
		if len(parts) == 2 {
			ip := parts[0]
			ipPortCount[ip]++
		}
	}

	// Update the metric with the count of open ports per IP
	for ip, count := range ipPortCount {
		mc.openPortsTotal.WithLabelValues(ip).Set(float64(count))
	}

	// Find IPs that had open ports previously but not now, and set their counts to zero
	prevIPs := extractIPsFromPorts(prevPorts)
	for ip := range prevIPs {
		if _, stillOpen := ipPortCount[ip]; !stillOpen {
			mc.openPortsTotal.WithLabelValues(ip).Set(0)
		}
	}
}

func extractIPsFromPorts(ports map[string]struct{}) map[string]struct{} {
	ips := make(map[string]struct{})
	for portKey := range ports {
		parts := strings.Split(portKey, ":")
		if len(parts) == 2 {
			ip := parts[0]
			ips[ip] = struct{}{}
		}
	}
	return ips
}

func (mc *MetricsCollector) storeCurrentScanInfo(targetKey string, newResults map[string]struct{}) {
	mc.scannedTargets.Store(targetKey, &ScanInfo{
		Ports:    newResults,
		LastScan: time.Now(),
	})
}
