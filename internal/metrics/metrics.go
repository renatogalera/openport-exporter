package metrics

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const metricNamespace = "openport"

// MetricsCollector encapsulates all Prometheus metrics.
type MetricsCollector struct {
    // Aggregated metric (bounded cardinality)
    scanTargetOpenPortsTotal *prometheus.GaugeVec
    scanDuration        *prometheus.GaugeVec
    taskQueueSizeMetric prometheus.Gauge
    scanTimeouts        *prometheus.CounterVec
    scannedTargets      sync.Map

	// New metrics
	hostUpCount           *prometheus.GaugeVec
	hostDownCount         *prometheus.GaugeVec
	scansSuccessful       *prometheus.CounterVec
	scansFailed           *prometheus.CounterVec
	lastScanTimestamp     *prometheus.GaugeVec
	portStateChanges      *prometheus.CounterVec
	scanDurationHistogram *prometheus.HistogramVec
}

// NewMetricsCollector creates and initializes a new MetricsCollector.
func NewMetricsCollector() *MetricsCollector {
    mc := &MetricsCollector{
        scanTargetOpenPortsTotal: prometheus.NewGaugeVec(
            prometheus.GaugeOpts{
                Namespace: metricNamespace,
                Name:      "scan_target_ports_open_total",
                Help:      "Total number of open ports for a given target, port_range and protocol in the last scan.",
            },
            []string{"target", "port_range", "protocol"},
        ),
        scanDuration: prometheus.NewGaugeVec(
            prometheus.GaugeOpts{
                Namespace: metricNamespace,
                Name:      "last_scan_duration_seconds",
                Help:      "Duration of the last port scan in seconds.",
            },
            []string{"target", "port_range", "protocol"},
        ),
        taskQueueSizeMetric: prometheus.NewGauge(
            prometheus.GaugeOpts{
                Namespace: metricNamespace,
                Name:      "task_queue_size",
                Help:      "The current size of the task queue.",
            },
        ),
        scanTimeouts: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Namespace: metricNamespace,
                Name:      "nmap_scan_timeouts_total",
                Help:      "Total number of Nmap scans that timed out.",
            },
            []string{"target", "port_range", "protocol"},
        ),
        // New metrics
        hostUpCount: prometheus.NewGaugeVec(
            prometheus.GaugeOpts{
                Namespace: metricNamespace,
                Name:      "nmap_host_up_count",
                Help:      "Number of hosts found up during the last scan for a target.",
            },
            []string{"target"},
        ),
        hostDownCount: prometheus.NewGaugeVec(
            prometheus.GaugeOpts{
                Namespace: metricNamespace,
                Name:      "nmap_host_down_count",
                Help:      "Number of hosts found down (unreachable) during the last scan for a target.",
            },
            []string{"target"},
        ),
        scansSuccessful: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Namespace: metricNamespace,
                Name:      "scans_successful_total",
                Help:      "Total number of successfully completed scans (no error) per target, port_range, and protocol.",
            },
            []string{"target", "port_range", "protocol"},
        ),
        // Added label "error_type"
        scansFailed: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Namespace: metricNamespace,
                Name:      "scans_failed_total",
                Help:      "Total number of scans that failed (encountered an error) per target, port_range, protocol, and error type.",
            },
            []string{"target", "port_range", "protocol", "error_type"},
        ),
        lastScanTimestamp: prometheus.NewGaugeVec(
            prometheus.GaugeOpts{
                Namespace: metricNamespace,
                Name:      "last_scan_timestamp_seconds",
                Help:      "Unix timestamp of the last scan for a given target, port_range, and protocol.",
            },
            []string{"target", "port_range", "protocol"},
        ),
        portStateChanges: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Namespace: metricNamespace,
                Name:      "port_state_changes_total",
                Help:      "Total number of port state changes (open -> closed or closed -> open) per target.",
            },
            []string{"target", "port_range", "protocol", "change_type"}, // "closed_to_open", "open_to_closed"
        ),
        scanDurationHistogram: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Namespace: metricNamespace,
                Name:      "scan_duration_seconds",
                Help:      "Histogram of scan durations in seconds.",
                Buckets:   prometheus.DefBuckets,
            },
            []string{"target", "port_range", "protocol"},
        ),
    }
    return mc
}

// GetScanDurationHistogram returns the scan duration histogram.
func (mc *MetricsCollector) GetScanDurationHistogram() *prometheus.HistogramVec {
	return mc.scanDurationHistogram
}

// Describe sends the super-set of all descriptors of metrics to the provided channel.
func (mc *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
    mc.scanTargetOpenPortsTotal.Describe(ch)
    mc.scanDuration.Describe(ch)
    mc.taskQueueSizeMetric.Describe(ch)
    mc.scanTimeouts.Describe(ch)

	// New metrics
	mc.hostUpCount.Describe(ch)
	mc.hostDownCount.Describe(ch)
	mc.scansSuccessful.Describe(ch)
	mc.scansFailed.Describe(ch)
	mc.lastScanTimestamp.Describe(ch)
	mc.portStateChanges.Describe(ch)
	mc.scanDurationHistogram.Describe(ch)
}

// Collect is called by the Prometheus registry when collecting metrics.
func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	mc.scanTargetOpenPortsTotal.Collect(ch)
	mc.scanDuration.Collect(ch)
	mc.taskQueueSizeMetric.Collect(ch)
    mc.scanTimeouts.Collect(ch)

	// New metrics
	mc.hostUpCount.Collect(ch)
	mc.hostDownCount.Collect(ch)
	mc.scansSuccessful.Collect(ch)
	mc.scansFailed.Collect(ch)
	mc.lastScanTimestamp.Collect(ch)
	mc.portStateChanges.Collect(ch)
	mc.scanDurationHistogram.Collect(ch)
}

// ------------------- EXISTING METHODS -------------------

// UpdateMetrics updates the metrics with new scan results (open ports).
func (mc *MetricsCollector) UpdateMetrics(targetKey string, newResults map[string]struct{}) {
	prevScanInfo := mc.getPreviousScanInfo(targetKey)
	// Record port state changes before updating current scan data.
	mc.updatePortStateChanges(targetKey, prevScanInfo.Ports, newResults)
    // Update aggregated open ports metric by target components.
    tgt, pr, proto := parseTargetKey(targetKey)
    mc.scanTargetOpenPortsTotal.WithLabelValues(tgt, pr, proto).Set(float64(len(newResults)))
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
// (removed) worker utilization gauge; not tracked

// ------------------- NEW METHODS -------------------

// UpdateHostCounts updates the number of hosts found up/down for a given target.
func (mc *MetricsCollector) UpdateHostCounts(target string, up, down int) {
	mc.hostUpCount.WithLabelValues(target).Set(float64(up))
	mc.hostDownCount.WithLabelValues(target).Set(float64(down))
}

// IncrementScanSuccess increments the counter for successful scans.
func (mc *MetricsCollector) IncrementScanSuccess(target, portRange, protocol string) {
	mc.scansSuccessful.WithLabelValues(target, portRange, protocol).Inc()
}

// IncrementScanFailure increments the counter for failed scans with an error type.
func (mc *MetricsCollector) IncrementScanFailure(target, portRange, protocol, errorType string) {
	mc.scansFailed.WithLabelValues(target, portRange, protocol, errorType).Inc()
}

// SetLastScanTimestamp sets the Unix timestamp of the last scan for a target.
func (mc *MetricsCollector) SetLastScanTimestamp(target, portRange, protocol string, ts time.Time) {
	mc.lastScanTimestamp.WithLabelValues(target, portRange, protocol).Set(float64(ts.Unix()))
}

// ------------------- PRIVATE METHODS -------------------

// ScanInfo holds information about a scan.
type ScanInfo struct {
    Ports    map[string]struct{}
    LastScan time.Time
}

func (mc *MetricsCollector) getPreviousScanInfo(targetKey string) *ScanInfo {
	prevScanInfoInterface, _ := mc.scannedTargets.Load(targetKey)
	if prevScanInfoInterface == nil {
		return &ScanInfo{Ports: make(map[string]struct{})}
	}
	return prevScanInfoInterface.(*ScanInfo)
}

func (mc *MetricsCollector) storeCurrentScanInfo(targetKey string, newResults map[string]struct{}) {
    mc.scannedTargets.Store(targetKey, &ScanInfo{
        Ports:    newResults,
        LastScan: time.Now(),
    })
}

// updatePortStateChanges tracks changes in port state between scans.
func (mc *MetricsCollector) updatePortStateChanges(targetKey string, prevPorts, newPorts map[string]struct{}) {
    tgt, pr, proto := parseTargetKey(targetKey)
    for portKey := range newPorts {
        if _, existed := prevPorts[portKey]; !existed {
            mc.portStateChanges.WithLabelValues(tgt, pr, proto, "closed_to_open").Inc()
        }
    }
    for portKey := range prevPorts {
        if _, stillOpen := newPorts[portKey]; !stillOpen {
            mc.portStateChanges.WithLabelValues(tgt, pr, proto, "open_to_closed").Inc()
        }
    }
}

// parseTargetKey extracts target, port_range, proto from the composite key "target_portRange_proto".
func parseTargetKey(k string) (string, string, string) {
    parts := strings.SplitN(k, "_", 3)
    if len(parts) != 3 {
        return k, "", "tcp"
    }
    return parts[0], parts[1], parts[2]
}

// StartSweeper starts a background eviction loop that removes stale scannedTargets
// and cleans the aggregated metric after the provided TTL. It stops when ctx is done.
func (mc *MetricsCollector) StartSweeper(ctx context.Context, ttl time.Duration) {
    if ttl <= 0 {
        return
    }
    ticker := time.NewTicker(ttl / 2)
    go func() {
        defer ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                now := time.Now()
                mc.scannedTargets.Range(func(key, value any) bool {
                    k := key.(string)
                    v := value.(*ScanInfo)
                    if now.Sub(v.LastScan) > ttl {
                        // Delete from cache and remove aggregated metric series
                        mc.scannedTargets.Delete(k)
                        tgt, pr, proto := parseTargetKey(k)
                        mc.scanTargetOpenPortsTotal.DeleteLabelValues(tgt, pr, proto)
                    }
                    return true
                })
            }
        }
    }()
}
