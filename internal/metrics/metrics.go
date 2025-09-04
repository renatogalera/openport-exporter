package metrics

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const metricNamespace = "openport"

// Collector encapsulates all Prometheus metrics.
type Collector struct {
	// Aggregated metric (bounded cardinality)
	scanTargetOpenPortsTotal *prometheus.GaugeVec
	scanDuration             *prometheus.GaugeVec
	// taskQueueSizeMetric removed in favor of schedulerQueueSize
	scanTimeouts   *prometheus.CounterVec
	scannedTargets sync.Map

	hostUpCount           *prometheus.GaugeVec
	hostDownCount         *prometheus.GaugeVec
	scansSuccessful       *prometheus.CounterVec
	scansFailed           *prometheus.CounterVec
	lastScanTimestamp     *prometheus.GaugeVec
	portStateChanges      *prometheus.CounterVec
	scanDurationHistogram *prometheus.HistogramVec

	// Background details (allowlisted & bounded)
	portOpen             *prometheus.GaugeVec // openport_port_open{alias,ip,port,protocol}
	detailsSeriesDropped prometheus.Counter   // openport_details_series_dropped_total
	detailedPortsMu      sync.Mutex
	detailedPorts        map[string]time.Time // key: alias|ip|port|proto

	sweeperTTL     atomic.Int64 // store as int64 nanoseconds
	perTargetTTLMu sync.Mutex
	perTargetTTL   map[string]time.Duration

	// sweeper runtime
	sweeperMu     sync.Mutex
	sweeperTicker *time.Ticker
	sweeperReset  chan struct{}

	// Scheduler/admin metrics (low cardinality)
	schedulerQueueSize        prometheus.Gauge
	schedulerRunning          prometheus.Gauge
	schedulerOldestPendingSec prometheus.Gauge
	tasksCreated              *prometheus.CounterVec   // {module}
	tasksCompleted            *prometheus.CounterVec   // {module,outcome}
	taskDurationSeconds       *prometheus.HistogramVec // {module}
	schedulerEnqueueFailed    prometheus.Counter
}

// NewMetricsCollector creates and initializes a new Collector.
func NewMetricsCollector() *Collector {
	mc := &Collector{
		scanTargetOpenPortsTotal: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricNamespace,
				Name:      "scan_target_ports_open",
				Help:      "Number of open ports for a given target, port_range and protocol in the last scan.",
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
		// deprecated: openport_task_queue_size removed
		scanTimeouts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricNamespace,
				Name:      "nmap_scan_timeouts_total",
				Help:      "Total number of Nmap scans that timed out.",
			},
			[]string{"target", "port_range", "protocol"},
		),
		hostUpCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricNamespace,
				Name:      "nmap_hosts_up",
				Help:      "Number of hosts found up during the last scan for a target.",
			},
			[]string{"target", "port_range", "protocol"},
		),
		hostDownCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricNamespace,
				Name:      "nmap_hosts_down",
				Help:      "Number of hosts found down (unreachable) during the last scan for a target.",
			},
			[]string{"target", "port_range", "protocol"},
		),
		scansSuccessful: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricNamespace,
				Name:      "scans_successful_total",
				Help:      "Total number of successfully completed scans (no error) per target, port_range, and protocol.",
			},
			[]string{"target", "port_range", "protocol"},
		),
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
			[]string{"target", "port_range", "protocol", "change_type"},
		),
		scanDurationHistogram: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricNamespace,
				Name:      "scan_duration_seconds",
				Help:      "Histogram of scan durations in seconds.",
				Buckets:   []float64{1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 900, 1200, 1800, 3600},
			},
			[]string{"target", "port_range", "protocol"},
		),

		portOpen: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: metricNamespace,
				Name:      "port_open",
				Help:      "1 if (alias/ip,port,protocol) is open (background allowlisted details only).",
			},
			[]string{"alias", "ip", "port", "protocol"},
		),
		detailsSeriesDropped: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricNamespace,
				Name:      "details_series_dropped_total",
				Help:      "Total number of background detail series drop events due to budget.",
			},
		),
		detailedPorts: make(map[string]time.Time),

		schedulerQueueSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "scheduler_queue_size",
			Help:      "Current size of the scheduler task queue.",
		}),
		schedulerRunning: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "scheduler_running",
			Help:      "Number of tasks currently running.",
		}),
		schedulerOldestPendingSec: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "scheduler_oldest_pending_seconds",
			Help:      "Age in seconds of the oldest pending task.",
		}),
		tasksCreated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "tasks_created_total",
			Help:      "Total number of tasks accepted for execution.",
		}, []string{"module"}),
		tasksCompleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "tasks_completed_total",
			Help:      "Total number of tasks completed, labeled by outcome.",
		}, []string{"module", "outcome"}),
		taskDurationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricNamespace,
			Name:      "task_duration_seconds",
			Help:      "Histogram of task durations in seconds.",
			Buckets:   []float64{1, 2, 5, 10, 20, 30, 60, 120, 300, 600, 900, 1200, 1800, 3600},
		}, []string{"module"}),
		schedulerEnqueueFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "scheduler_enqueue_failed_total",
			Help:      "Number of failed enqueues due to backpressure in scheduler.",
		}),
		perTargetTTL: make(map[string]time.Duration),
	}
	return mc
}

// GetScanDurationHistogram returns the scan duration histogram.
func (mc *Collector) GetScanDurationHistogram() *prometheus.HistogramVec {
	return mc.scanDurationHistogram
}

// Describe sends the super-set of all descriptors of metrics to the provided channel.
func (mc *Collector) Describe(ch chan<- *prometheus.Desc) {
	mc.scanTargetOpenPortsTotal.Describe(ch)
	mc.scanDuration.Describe(ch)
	// deprecated: taskQueueSizeMetric removed
	mc.scanTimeouts.Describe(ch)
	mc.hostUpCount.Describe(ch)
	mc.hostDownCount.Describe(ch)
	mc.scansSuccessful.Describe(ch)
	mc.scansFailed.Describe(ch)
	mc.lastScanTimestamp.Describe(ch)
	mc.portStateChanges.Describe(ch)
	mc.scanDurationHistogram.Describe(ch)

	mc.portOpen.Describe(ch)
	mc.detailsSeriesDropped.Describe(ch)

	mc.schedulerQueueSize.Describe(ch)
	mc.schedulerRunning.Describe(ch)
	mc.schedulerOldestPendingSec.Describe(ch)
	mc.tasksCreated.Describe(ch)
	mc.tasksCompleted.Describe(ch)
	mc.taskDurationSeconds.Describe(ch)
	mc.schedulerEnqueueFailed.Describe(ch)
}

// Collect is called by the Prometheus registry when collecting metrics.
func (mc *Collector) Collect(ch chan<- prometheus.Metric) {
	mc.scanTargetOpenPortsTotal.Collect(ch)
	mc.scanDuration.Collect(ch)
	// deprecated: taskQueueSizeMetric removed
	mc.scanTimeouts.Collect(ch)
	mc.hostUpCount.Collect(ch)
	mc.hostDownCount.Collect(ch)
	mc.scansSuccessful.Collect(ch)
	mc.scansFailed.Collect(ch)
	mc.lastScanTimestamp.Collect(ch)
	mc.portStateChanges.Collect(ch)
	mc.scanDurationHistogram.Collect(ch)

	mc.portOpen.Collect(ch)
	mc.detailsSeriesDropped.Collect(ch)

	mc.schedulerQueueSize.Collect(ch)
	mc.schedulerRunning.Collect(ch)
	mc.schedulerOldestPendingSec.Collect(ch)
	mc.tasksCreated.Collect(ch)
	mc.tasksCompleted.Collect(ch)
	mc.taskDurationSeconds.Collect(ch)
	mc.schedulerEnqueueFailed.Collect(ch)
}

// IncSchedulerEnqueueFailed increments the scheduler enqueue failure counter.
func (mc *Collector) IncSchedulerEnqueueFailed() { mc.schedulerEnqueueFailed.Inc() }

// SetSweeperTTL updates the TTL used by the sweeper (hot-reload).
func (mc *Collector) SetSweeperTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	mc.sweeperTTL.Store(int64(ttl))
	// Notify the sweeper to rebuild ticker if running
	mc.sweeperMu.Lock()
	ch := mc.sweeperReset
	mc.sweeperMu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (mc *Collector) getSweeperTTL() time.Duration {
	v := mc.sweeperTTL.Load()
	return time.Duration(v)
}

// ------------------- EXISTING METHODS -------------------

// UpdateMetrics updates the metrics with new scan results (open ports).
func (mc *Collector) UpdateMetrics(targetKey string, newResults map[string]struct{}) {
	prevScanInfo := mc.getPreviousScanInfo(targetKey)
	// Record port state changes before updating current scan data.
	mc.updatePortStateChanges(targetKey, prevScanInfo.Ports, newResults)
	// Update aggregated open ports metric by target components.
	tgt, pr, proto := parseTargetKey(targetKey)
	mc.scanTargetOpenPortsTotal.WithLabelValues(tgt, pr, proto).Set(float64(len(newResults)))
	mc.storeCurrentScanInfo(targetKey, newResults)
}

// CanScan checks if a new scan can be performed based on the scan interval.
func (mc *Collector) CanScan(targetKey string, scanInterval time.Duration) bool {
	infoInterface, exists := mc.scannedTargets.Load(targetKey)
	if !exists {
		return true
	}
	info := infoInterface.(*ScanInfo)
	return time.Since(info.LastScan) >= scanInterval
}

// RegisterScan registers a new scan with the current time.
func (mc *Collector) RegisterScan(targetKey string) {
	mc.scannedTargets.Store(targetKey, &ScanInfo{
		Ports:    make(map[string]struct{}),
		LastScan: time.Now(),
	})
}

// IncrementScanTimeout increments the scan timeout counter.
func (mc *Collector) IncrementScanTimeout(target, portRange, protocol string) {
	mc.scanTimeouts.WithLabelValues(target, portRange, protocol).Inc()
}

// ObserveScanDuration sets the duration metric of a scan.
func (mc *Collector) ObserveScanDuration(target, portRange, protocol string, duration float64) {
	mc.scanDuration.WithLabelValues(target, portRange, protocol).Set(duration)
}

// UpdateTaskQueueSize updates the task queue size metric.
func (mc *Collector) UpdateTaskQueueSize(queueSize int) {
	mc.schedulerQueueSize.Set(float64(queueSize))
}

// --- Scheduler/admin helpers ---
func (mc *Collector) SetSchedulerRunning(n int) { mc.schedulerRunning.Set(float64(n)) }

func (mc *Collector) SetOldestPendingAge(seconds float64) {
	if seconds < 0 {
		seconds = 0
	}
	mc.schedulerOldestPendingSec.Set(seconds)
}

func (mc *Collector) IncTasksCreated(module string) {
	mc.tasksCreated.WithLabelValues(module).Inc()
}

func (mc *Collector) IncTasksCompleted(module, outcome string) {
	mc.tasksCompleted.WithLabelValues(module, outcome).Inc()
}

func (mc *Collector) ObserveTaskDuration(module string, seconds float64) {
	mc.taskDurationSeconds.WithLabelValues(module).Observe(seconds)
}

// SetPerTargetTTL configures a custom TTL for the given aggregated key (target_portRange_proto).
func (mc *Collector) SetPerTargetTTL(key string, ttl time.Duration) {
	mc.perTargetTTLMu.Lock()
	if ttl > 0 {
		mc.perTargetTTL[key] = ttl
	} else {
		delete(mc.perTargetTTL, key)
	}
	mc.perTargetTTLMu.Unlock()
}

// ------------------- NEW METHODS -------------------

// UpdateHostCounts updates the number of hosts found up/down for a given target.
func (mc *Collector) UpdateHostCounts(target, portRange, protocol string, up, down int) {
	mc.hostUpCount.WithLabelValues(target, portRange, protocol).Set(float64(up))
	mc.hostDownCount.WithLabelValues(target, portRange, protocol).Set(float64(down))
}

// IncrementScanSuccess increments the counter for successful scans.
func (mc *Collector) IncrementScanSuccess(target, portRange, protocol string) {
	mc.scansSuccessful.WithLabelValues(target, portRange, protocol).Inc()
}

// IncrementScanFailure increments the counter for failed scans with an error type.
func (mc *Collector) IncrementScanFailure(target, portRange, protocol, errorType string) {
	mc.scansFailed.WithLabelValues(target, portRange, protocol, errorType).Inc()
}

// SetLastScanTimestamp sets the Unix timestamp of the last scan for a target.
func (mc *Collector) SetLastScanTimestamp(target, portRange, protocol string, ts time.Time) {
	mc.lastScanTimestamp.WithLabelValues(target, portRange, protocol).Set(float64(ts.Unix()))
}

// ------------------- PRIVATE METHODS -------------------

// ScanInfo holds information about a scan.
type ScanInfo struct {
	Ports    map[string]struct{}
	LastScan time.Time
}

func (mc *Collector) getPreviousScanInfo(targetKey string) *ScanInfo {
	prevScanInfoInterface, _ := mc.scannedTargets.Load(targetKey)
	if prevScanInfoInterface == nil {
		return &ScanInfo{Ports: make(map[string]struct{})}
	}
	return prevScanInfoInterface.(*ScanInfo)
}

func (mc *Collector) storeCurrentScanInfo(targetKey string, newResults map[string]struct{}) {
	mc.scannedTargets.Store(targetKey, &ScanInfo{
		Ports:    newResults,
		LastScan: time.Now(),
	})
}

// updatePortStateChanges tracks changes in port state between scans.
func (mc *Collector) updatePortStateChanges(targetKey string, prevPorts, newPorts map[string]struct{}) {
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
func (mc *Collector) StartSweeper(ctx context.Context, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	mc.SetSweeperTTL(ttl)
	mc.sweeperMu.Lock()
	if mc.sweeperReset == nil {
		mc.sweeperReset = make(chan struct{}, 1)
	}
	// Initialize ticker
	if mc.sweeperTicker != nil {
		mc.sweeperTicker.Stop()
	}
	mc.sweeperTicker = time.NewTicker(ttl / 2)
	ticker := mc.sweeperTicker
	reset := mc.sweeperReset
	mc.sweeperMu.Unlock()

	go func() {
		defer func() {
			mc.sweeperMu.Lock()
			if mc.sweeperTicker != nil {
				mc.sweeperTicker.Stop()
				mc.sweeperTicker = nil
			}
			mc.sweeperMu.Unlock()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-reset:
				// Rebuild ticker with new TTL
				newTTL := mc.getSweeperTTL()
				if newTTL <= 0 {
					newTTL = time.Minute
				}
				mc.sweeperMu.Lock()
				if mc.sweeperTicker != nil {
					mc.sweeperTicker.Stop()
				}
				mc.sweeperTicker = time.NewTicker(newTTL / 2)
				ticker = mc.sweeperTicker
				mc.sweeperMu.Unlock()
			case <-ticker.C:
				defaultTTL := mc.getSweeperTTL()
				now := time.Now()
				mc.scannedTargets.Range(func(key, value any) bool {
					k := key.(string)
					v := value.(*ScanInfo)
					mc.perTargetTTLMu.Lock()
					tttl, ok := mc.perTargetTTL[k]
					mc.perTargetTTLMu.Unlock()
					eff := defaultTTL
					if ok && tttl > 0 {
						eff = tttl
					}
					if now.Sub(v.LastScan) > eff {
						mc.scannedTargets.Delete(k)
						tgt, pr, proto := parseTargetKey(k)
						mc.deleteAllTargetSeries(tgt, pr, proto)
					}
					return true
				})
				mc.detailedPortsMu.Lock()
				for k, last := range mc.detailedPorts {
					if now.Sub(last) > defaultTTL {
						parts := strings.Split(k, "|")
						if len(parts) == 4 {
							_ = mc.portOpen.DeleteLabelValues(
								parts[0],
								parts[1],
								parts[2],
								parts[3],
							)
						}
						delete(mc.detailedPorts, k)
					}
				}
				mc.detailedPortsMu.Unlock()
			}
		}
	}()
}

// ------------------- BACKGROUND DETAILS HELPERS -------------------

// DetailedSeriesCount returns the current number of detailed port series.
func (mc *Collector) DetailedSeriesCount() int {
	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()
	return len(mc.detailedPorts)
}

// IncrementDroppedSeries increments the counter for dropped detail series.
func (mc *Collector) IncrementDroppedSeries() {
	mc.detailsSeriesDropped.Inc()
}

// SetDetailedPortOpen sets a detailed port as open and tracks it for TTL management.
// This method is deprecated in favor of SetDetailedPortOpenWithBudget for thread-safe budget enforcement.
func (mc *Collector) SetDetailedPortOpen(alias, ip, port, proto string) {
	mc.portOpen.WithLabelValues(alias, ip, port, proto).Set(1)
	key := strings.Join([]string{alias, ip, port, proto}, "|")
	mc.detailedPortsMu.Lock()
	mc.detailedPorts[key] = time.Now()
	mc.detailedPortsMu.Unlock()
}

// SetDetailedPortOpenWithBudget atomically checks the series budget and adds a detailed port metric.
// Returns true if the port was added, false if the budget was exceeded.
// This method provides thread-safe budget enforcement for multi-worker scenarios.
func (mc *Collector) SetDetailedPortOpenWithBudget(alias, ip, port, proto string, budget int) bool {
	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()

	// Check budget constraint atomically
	if budget > 0 && len(mc.detailedPorts) >= budget {
		return false // Budget exceeded
	}

	// Add the metric and track it
	key := strings.Join([]string{alias, ip, port, proto}, "|")
	mc.detailedPorts[key] = time.Now()
	mc.portOpen.WithLabelValues(alias, ip, port, proto).Set(1)

	return true
}

// DeleteDetailedPort removes a detailed port metric and its tracking entry.
func (mc *Collector) DeleteDetailedPort(alias, ip, port, proto string) {
	_ = mc.portOpen.DeleteLabelValues(alias, ip, port, proto)
	key := strings.Join([]string{alias, ip, port, proto}, "|")
	mc.detailedPortsMu.Lock()
	delete(mc.detailedPorts, key)
	mc.detailedPortsMu.Unlock()
}

// DebugDumpDetailed returns debug information about detailed series (for debug/tests only).
func (mc *Collector) DebugDumpDetailed() string {
	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()
	return fmt.Sprintf("%d-detailed-series", len(mc.detailedPorts))
}

// deleteAllTargetSeries removes all known series for a target/port_range/protocol tuple.
func (mc *Collector) deleteAllTargetSeries(tgt, pr, proto string) {
	_ = mc.scanTargetOpenPortsTotal.DeleteLabelValues(tgt, pr, proto)
	_ = mc.scanDuration.DeleteLabelValues(tgt, pr, proto)
	_ = mc.lastScanTimestamp.DeleteLabelValues(tgt, pr, proto)
	_ = mc.scanDurationHistogram.DeleteLabelValues(tgt, pr, proto)
	_ = mc.hostUpCount.DeleteLabelValues(tgt, pr, proto)
	_ = mc.hostDownCount.DeleteLabelValues(tgt, pr, proto)
	// Also delete counters labeled by target
	_ = mc.scansSuccessful.DeleteLabelValues(tgt, pr, proto)
	// Known error types
	for _, et := range []string{"timeout", "permission", "other", "scanner_creation"} {
		_ = mc.scansFailed.DeleteLabelValues(tgt, pr, proto, et)
	}
	// Optional timeouts duplicate counter
	_ = mc.scanTimeouts.DeleteLabelValues(tgt, pr, proto)
	// Port state changes for both directions
	for _, ct := range []string{"closed_to_open", "open_to_closed"} {
		_ = mc.portStateChanges.DeleteLabelValues(tgt, pr, proto, ct)
	}
}
