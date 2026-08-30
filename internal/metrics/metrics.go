package metrics

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
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
	scanTimeouts     *prometheus.CounterVec
	scannedTargets   sync.Map
	scheduledTargets sync.Map // map[string]*scheduledScanInfo
	scanSequence     atomic.Uint64
	inFlightScans    map[DetailedSource]map[uint64]struct{}

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
	detailedPorts        map[DetailedPort]*detailedSeriesInfo
	detailedPortSources  map[DetailedSource]*detailedScanInfo
	detailedSourceTTLs   []DetailedSourceTTLRule
	detailedSeriesBudget int
	detailedGeneration   uint64
	detailedEnabled      bool
	stateUpdateMu        sync.Mutex
	now                  func() time.Time

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
				Help:      "Presence-only series with value 1 while an allowlisted port is open.",
			},
			[]string{"alias", "ip", "port", "protocol"},
		),
		detailsSeriesDropped: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: metricNamespace,
				Name:      "details_series_dropped_total",
				Help:      "Total budget drop events, deduplicated within each scan result, including immediate evictions.",
			},
		),
		detailedPorts:       make(map[DetailedPort]*detailedSeriesInfo),
		detailedPortSources: make(map[DetailedSource]*detailedScanInfo),
		detailedEnabled:     true,
		now:                 time.Now,
		inFlightScans:       make(map[DetailedSource]map[uint64]struct{}),

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
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()
	mc.setSweeperTTL(ttl)
}

func (mc *Collector) setSweeperTTL(ttl time.Duration) {
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

// UpdateMetrics updates the aggregate metrics with new scan results.
func (mc *Collector) UpdateMetrics(targetKey string, newResults map[string]struct{}) {
	mc.UpdateMetricsForScan(targetKey, newResults, 0)
}

// UpdateMetricsForScan updates aggregate state unless a newer scan of the same
// source has already completed. A zero sequence preserves the legacy behavior
// for callers that do not coordinate concurrent scans.
func (mc *Collector) UpdateMetricsForScan(
	targetKey string,
	newResults map[string]struct{},
	scanSequence uint64,
) bool {
	return mc.updateMetricsForScanGeneration(targetKey, newResults, scanSequence, 0, false)
}

// UpdateMetricsForScanGeneration additionally rejects results built from an
// obsolete lifecycle generation.
func (mc *Collector) UpdateMetricsForScanGeneration(
	targetKey string,
	newResults map[string]struct{},
	scanSequence uint64,
	generation uint64,
) bool {
	return mc.updateMetricsForScanGeneration(targetKey, newResults, scanSequence, generation, true)
}

func (mc *Collector) updateMetricsForScanGeneration(
	targetKey string,
	newResults map[string]struct{},
	scanSequence uint64,
	generation uint64,
	enforceGeneration bool,
) bool {
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()
	if enforceGeneration && generation != mc.detailedGeneration {
		return false
	}
	return mc.updateMetrics(targetKey, newResults, scanSequence)
}

// DetailedPortUpdate contains the allowlisted detailed state derived from one
// successful scan. Generation identifies the background-details configuration
// used to build Ports. ScanSequence rejects an older concurrent result, while
// Source provides a delimiter-safe ownership identity.
type DetailedPortUpdate struct {
	Ports        []DetailedPort
	Generation   uint64
	ScanSequence uint64
	Source       DetailedSource
}

// UpdateMetricsAndDetailedPorts updates the aggregate scan state and reconciles
// the presence-only detailed series owned by that scan target.
//
// A detailed series remains exposed while at least one current scan target
// reports the same label set as open. This avoids deleting shared series when
// scan ranges overlap or when include_ip=false collapses multiple IPs into one
// label set. The return value is the number of unique series from this scan that
// could not be admitted by the configured budget.
func (mc *Collector) UpdateMetricsAndDetailedPorts(
	targetKey string,
	newResults map[string]struct{},
	update DetailedPortUpdate,
) int {
	dropped, _ := mc.UpdateMetricsAndDetailedPortsForScan(targetKey, newResults, update)
	return dropped
}

// UpdateMetricsAndDetailedPortsForScan also reports whether the aggregate
// last-result snapshot accepted this observation. Detail reconciliation still
// runs independently so an obsolete aggregate task cannot block a valid detail
// generation.
func (mc *Collector) UpdateMetricsAndDetailedPortsForScan(
	targetKey string,
	newResults map[string]struct{},
	update DetailedPortUpdate,
) (int, bool) {
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()

	aggregateAccepted := false
	if update.Generation == mc.detailedGeneration {
		aggregateAccepted = mc.updateMetrics(targetKey, newResults, update.ScanSequence)
	}
	dropped := mc.reconcileDetailedPorts(targetKey, update)
	if dropped > 0 {
		mc.detailsSeriesDropped.Add(float64(dropped))
	}
	return dropped, aggregateAccepted
}

// ConfigureDetailedMetrics applies the active background-details generation and
// budget. resetState must be true when labels or the allowlist changed because
// existing series can no longer be validated against the new definition.
func (mc *Collector) ConfigureDetailedMetrics(
	generation uint64,
	enabled bool,
	budget int,
	resetState bool,
) {
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()

	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()
	mc.configureDetailedMetricsLocked(generation, enabled, budget, resetState)
}

func (mc *Collector) configureDetailedMetricsLocked(
	generation uint64,
	enabled bool,
	budget int,
	resetState bool,
) bool {
	if generation < mc.detailedGeneration {
		return false
	}
	if resetState || !enabled {
		mc.clearDetailedPortsLocked()
	}
	mc.detailedGeneration = generation
	mc.detailedEnabled = enabled
	mc.detailedSeriesBudget = budget
	if !enabled {
		return true
	}

	evicted := mc.enforceDetailedBudgetLocked(budget)
	if evicted > 0 {
		mc.detailsSeriesDropped.Add(float64(evicted))
	}
	return true
}

// ConfigureDetailedMetricsWithSourceTTLs installs the generation, lifecycle
// policy, budget, and scheduled-source TTL rules as one atomic reload step.
func (mc *Collector) ConfigureDetailedMetricsWithSourceTTLs(
	generation uint64,
	enabled bool,
	budget int,
	resetState bool,
	rules []DetailedSourceTTLRule,
) {
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()

	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()

	if !mc.configureDetailedMetricsLocked(generation, enabled, budget, resetState) {
		return
	}
	mc.configureDetailedSourceTTLsLocked(rules)
}

// ConfigureScanLifecycle applies all reloadable state used by the scheduler,
// aggregate sweeper, and detailed reconciler in one transaction.
func (mc *Collector) ConfigureScanLifecycle(
	generation uint64,
	enabled bool,
	budget int,
	resetState bool,
	rules []DetailedSourceTTLRule,
	scheduledTTLs map[string]time.Duration,
	globalTTL time.Duration,
) {
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()

	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()

	if !mc.configureDetailedMetricsLocked(generation, enabled, budget, resetState) {
		return
	}
	mc.setSweeperTTL(globalTTL)
	mc.configureDetailedSourceTTLsLocked(rules)
	mc.configureScheduledTargetTTLsLocked(scheduledTTLs)
}

// ConfigureDetailedSourceTTLs atomically replaces the live scheduled-source
// TTL policy and immediately reapplies it to already-owned detail state.
func (mc *Collector) ConfigureDetailedSourceTTLs(
	generation uint64,
	rules []DetailedSourceTTLRule,
) {
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()

	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()

	if generation != mc.detailedGeneration {
		return
	}
	mc.configureDetailedSourceTTLsLocked(rules)
}

func (mc *Collector) configureDetailedSourceTTLsLocked(rules []DetailedSourceTTLRule) {
	mc.detailedSourceTTLs = normalizeDetailedSourceTTLRules(rules)
	for sourceID, source := range mc.detailedPortSources {
		source.MinTTL = mc.detailedSourceTTLLocked(sourceID)
	}
}

func (mc *Collector) updateMetrics(
	targetKey string,
	newResults map[string]struct{},
	scanSequence uint64,
) bool {
	prevScanInfo := mc.getPreviousScanInfo(targetKey)
	if scanSequence > 0 && prevScanInfo.Sequence >= scanSequence {
		return false
	}
	// Record port state changes before updating current scan data.
	mc.updatePortStateChanges(targetKey, prevScanInfo.Ports, newResults)
	// Update aggregated open ports metric by target components.
	tgt, pr, proto := parseTargetKey(targetKey)
	mc.scanTargetOpenPortsTotal.WithLabelValues(tgt, pr, proto).Set(float64(len(newResults)))
	mc.storeCurrentScanInfo(targetKey, newResults, scanSequence)
	return true
}

// CanScan checks if a new scan can be performed based on the scan interval.
func (mc *Collector) CanScan(targetKey string, scanInterval time.Duration) bool {
	return mc.CanScanForGeneration(targetKey, scanInterval, 0)
}

// CanScanForGeneration makes a source immediately eligible when its last
// enqueue belongs to an older detail topology.
func (mc *Collector) CanScanForGeneration(
	targetKey string,
	scanInterval time.Duration,
	generation uint64,
) bool {
	lastScheduled, exists := mc.scheduledTargets.Load(targetKey)
	if !exists {
		return true
	}
	info := lastScheduled.(*scheduledScanInfo)
	if info.Generation != generation {
		return true
	}
	return mc.nowTime().Sub(info.EnqueuedAt) >= scanInterval
}

// RegisterScan records when a scheduled scan was enqueued without overwriting
// the last successful result used by lifecycle and transition metrics.
func (mc *Collector) RegisterScan(targetKey string) {
	mc.RegisterScanForGeneration(targetKey, 0)
}

// RegisterScanForGeneration records an enqueue against its detail topology.
func (mc *Collector) RegisterScanForGeneration(targetKey string, generation uint64) {
	mc.scheduledTargets.Store(targetKey, &scheduledScanInfo{
		EnqueuedAt: mc.nowTime(),
		Generation: generation,
	})
}

// NextScanSequence returns a process-local monotonic observation sequence.
// Scans capture it before starting so older, slower results cannot overwrite a
// newer successful observation of the same source.
func (mc *Collector) NextScanSequence() uint64 {
	return mc.scanSequence.Add(1)
}

// BeginScan registers an in-flight observation and returns its monotonic
// sequence. Tracking prevents an ordering tombstone from expiring while an
// older scan can still complete.
func (mc *Collector) BeginScan(source DetailedSource) uint64 {
	source = normalizeDetailedSource(source)
	mc.stateUpdateMu.Lock()
	sequence := mc.NextScanSequence()
	active := mc.inFlightScans[source]
	if active == nil {
		active = make(map[uint64]struct{})
		mc.inFlightScans[source] = active
	}
	active[sequence] = struct{}{}
	mc.stateUpdateMu.Unlock()
	return sequence
}

// EndScan removes a previously registered in-flight observation.
func (mc *Collector) EndScan(source DetailedSource, sequence uint64) {
	if sequence == 0 {
		return
	}
	source = normalizeDetailedSource(source)
	mc.stateUpdateMu.Lock()
	if active := mc.inFlightScans[source]; active != nil {
		delete(active, sequence)
		if len(active) == 0 {
			delete(mc.inFlightScans, source)
		}
	}
	mc.stateUpdateMu.Unlock()
}

func (mc *Collector) hasOlderInFlightLocked(source DetailedSource, sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	for activeSequence := range mc.inFlightScans[source] {
		if activeSequence < sequence {
			return true
		}
	}
	return false
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

// ConfigureScheduledTargetTTLs replaces the live scheduler retention policy.
// Removed targets lose their enqueue timestamps so re-adding them schedules an
// immediate scan; interval increases take effect before the new config is read.
func (mc *Collector) ConfigureScheduledTargetTTLs(ttls map[string]time.Duration) {
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()
	mc.configureScheduledTargetTTLsLocked(ttls)
}

func (mc *Collector) configureScheduledTargetTTLsLocked(ttls map[string]time.Duration) {
	normalized := make(map[string]time.Duration, len(ttls))
	validTargets := make(map[string]struct{}, len(ttls))
	for key, ttl := range ttls {
		if ttl > 0 {
			normalized[key] = ttl
			validTargets[key] = struct{}{}
		}
	}
	mc.perTargetTTLMu.Lock()
	mc.perTargetTTL = normalized
	mc.perTargetTTLMu.Unlock()
	mc.scheduledTargets.Range(func(key, _ any) bool {
		if _, exists := validTargets[key.(string)]; !exists {
			mc.scheduledTargets.Delete(key)
		}
		return true
	})
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

// UpdateLastResultMetricsForScan writes last-result gauges only if sequence is
// still the accepted observation for this source and its lifecycle generation
// remains active. The validation and writes share stateUpdateMu so an older
// scan cannot overwrite gauges after a newer result wins.
func (mc *Collector) UpdateLastResultMetricsForScan(
	targetKey string,
	scanSequence uint64,
	generation uint64,
	completedAt time.Time,
	duration float64,
	durationEnabled bool,
	hostsUp int,
	hostsDown int,
) bool {
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()
	if generation != mc.detailedGeneration {
		return false
	}
	stored, exists := mc.scannedTargets.Load(targetKey)
	if !exists || stored.(*ScanInfo).Sequence != scanSequence {
		return false
	}
	target, portRange, protocol := parseTargetKey(targetKey)
	mc.lastScanTimestamp.WithLabelValues(target, portRange, protocol).Set(float64(completedAt.Unix()))
	if durationEnabled {
		mc.scanDuration.WithLabelValues(target, portRange, protocol).Set(duration)
	}
	mc.hostUpCount.WithLabelValues(target, portRange, protocol).Set(float64(hostsUp))
	mc.hostDownCount.WithLabelValues(target, portRange, protocol).Set(float64(hostsDown))
	return true
}

// ------------------- PRIVATE METHODS -------------------

// ScanInfo holds information about a scan.
type ScanInfo struct {
	Ports    map[string]struct{}
	LastScan time.Time
	Sequence uint64
}

type scheduledScanInfo struct {
	EnqueuedAt time.Time
	Generation uint64
}

// DetailedPort contains the labels for one openport_port_open series.
type DetailedPort struct {
	Alias    string
	IP       string
	Port     string
	Protocol string
}

// DetailedSource identifies the scan tuple that authoritatively reconciles a
// set of detailed series. A structured key avoids delimiter collisions.
type DetailedSource struct {
	Target    string
	PortRange string
	Protocol  string
}

// DetailedSourceTTLRule keeps scheduled detail state alive for at least the
// configured source cadence. Target may be an IP or CIDR; child shards inherit
// the rule when port range and protocol also match.
type DetailedSourceTTLRule struct {
	Source DetailedSource
	MinTTL time.Duration
}

// detailedScanInfo stores the admitted series and ordering tombstone for the
// latest successful detailed result from one scan source. Empty results are
// retained until TTL so an older concurrent scan cannot restore closed state.
type detailedScanInfo struct {
	Ports    map[DetailedPort]struct{}
	LastScan time.Time
	MinTTL   time.Duration
	Sequence uint64
}

type detailedSeriesInfo struct {
	Owners map[DetailedSource]struct{}
}

func (mc *Collector) getPreviousScanInfo(targetKey string) *ScanInfo {
	prevScanInfoInterface, _ := mc.scannedTargets.Load(targetKey)
	if prevScanInfoInterface == nil {
		return &ScanInfo{Ports: make(map[string]struct{})}
	}
	return prevScanInfoInterface.(*ScanInfo)
}

func (mc *Collector) storeCurrentScanInfo(
	targetKey string,
	newResults map[string]struct{},
	scanSequence uint64,
) {
	mc.scannedTargets.Store(targetKey, &ScanInfo{
		Ports:    newResults,
		LastScan: mc.nowTime(),
		Sequence: scanSequence,
	})
}

func (mc *Collector) nowTime() time.Time {
	if mc.now == nil {
		return time.Now()
	}
	return mc.now()
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
	mc.sweeperTicker = time.NewTicker(sweeperInterval(ttl))
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
				mc.sweeperTicker = time.NewTicker(sweeperInterval(newTTL))
				ticker = mc.sweeperTicker
				mc.sweeperMu.Unlock()
			case <-ticker.C:
				mc.sweepOnce(mc.nowTime())
			}
		}
	}()
}

func sweeperInterval(ttl time.Duration) time.Duration {
	interval := ttl / 2
	if interval <= 0 {
		return time.Nanosecond
	}
	return interval
}

func (mc *Collector) sweepOnce(now time.Time) {
	mc.stateUpdateMu.Lock()
	defer mc.stateUpdateMu.Unlock()
	defaultTTL := mc.getSweeperTTL()
	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()

	mc.scannedTargets.Range(func(key, value any) bool {
		k := key.(string)
		v := value.(*ScanInfo)
		mc.perTargetTTLMu.Lock()
		targetTTL, ok := mc.perTargetTTL[k]
		mc.perTargetTTLMu.Unlock()
		effectiveTTL := defaultTTL
		if ok && targetTTL > effectiveTTL {
			effectiveTTL = targetTTL
		}
		if sourceTTL := mc.detailedSourceTTLLocked(detailedSourceFromTargetKey(k)); sourceTTL > effectiveTTL {
			effectiveTTL = sourceTTL
		}
		if metricStateExpired(now, v.LastScan, effectiveTTL) &&
			!mc.hasOlderInFlightLocked(detailedSourceFromTargetKey(k), v.Sequence) {
			mc.scannedTargets.Delete(k)
			tgt, pr, proto := parseTargetKey(k)
			mc.deleteAllTargetSeries(tgt, pr, proto)
		}
		return true
	})
	mc.scheduledTargets.Range(func(key, value any) bool {
		k := key.(string)
		mc.perTargetTTLMu.Lock()
		targetTTL, ok := mc.perTargetTTL[k]
		mc.perTargetTTLMu.Unlock()
		effectiveTTL := defaultTTL
		if ok && targetTTL > effectiveTTL {
			effectiveTTL = targetTTL
		}
		if metricStateExpired(now, value.(*scheduledScanInfo).EnqueuedAt, effectiveTTL) {
			mc.scheduledTargets.Delete(key)
		}
		return true
	})

	for sourceID, source := range mc.detailedPortSources {
		effectiveTTL := defaultTTL
		if source.MinTTL > effectiveTTL {
			effectiveTTL = source.MinTTL
		}
		if metricStateExpired(now, source.LastScan, effectiveTTL) &&
			!mc.hasOlderInFlightLocked(sourceID, source.Sequence) {
			mc.removeDetailedSourceLocked(sourceID)
		}
	}
}

func metricStateExpired(now, lastScan time.Time, ttl time.Duration) bool {
	return ttl > 0 && !now.Before(lastScan.Add(ttl))
}

// ------------------- BACKGROUND DETAILS HELPERS -------------------

// DetailedSeriesCount returns the current number of detailed port series.
func (mc *Collector) DetailedSeriesCount() int {
	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()
	return len(mc.detailedPorts)
}

func (mc *Collector) reconcileDetailedPorts(
	targetKey string,
	update DetailedPortUpdate,
) int {
	mc.detailedPortsMu.Lock()
	defer mc.detailedPortsMu.Unlock()

	if !mc.detailedEnabled || update.Generation != mc.detailedGeneration {
		return 0
	}
	sourceID := normalizeDetailedSource(update.Source)
	if sourceID == (DetailedSource{}) {
		sourceID = detailedSourceFromTargetKey(targetKey)
	}
	previous := mc.detailedPortSources[sourceID]
	if update.ScanSequence > 0 && previous != nil && previous.Sequence >= update.ScanSequence {
		return 0
	}

	currentPorts := make(map[DetailedPort]struct{}, len(update.Ports))
	for _, port := range update.Ports {
		currentPorts[normalizeDetailedPort(port)] = struct{}{}
	}

	// Remove closed ports before admitting new ones so capacity released by this
	// scan can be reused immediately.
	if previous != nil {
		for port := range previous.Ports {
			if _, stillOpen := currentPorts[port]; !stillOpen {
				mc.removeDetailedOwnerLocked(port, sourceID)
			}
		}
	}

	orderedPorts := make([]DetailedPort, 0, len(currentPorts))
	for port := range currentPorts {
		orderedPorts = append(orderedPorts, port)
	}
	sortDetailedPorts(orderedPorts)

	var admitted map[DetailedPort]struct{}
	dropped := 0
	for _, port := range orderedPorts {
		series := mc.detailedPorts[port]
		if series == nil {
			if mc.detailedSeriesBudget > 0 && len(mc.detailedPorts) >= mc.detailedSeriesBudget {
				dropped++
				continue
			}
			series = &detailedSeriesInfo{Owners: make(map[DetailedSource]struct{})}
			mc.detailedPorts[port] = series
			setDetailedPortMetric(mc.portOpen, port)
		}
		series.Owners[sourceID] = struct{}{}
		if admitted == nil {
			admitted = make(map[DetailedPort]struct{})
		}
		admitted[port] = struct{}{}
	}

	sequence := update.ScanSequence
	if sequence == 0 && previous != nil {
		sequence = previous.Sequence
	}
	mc.detailedPortSources[sourceID] = &detailedScanInfo{
		Ports:    admitted,
		LastScan: mc.nowTime(),
		MinTTL:   mc.detailedSourceTTLLocked(sourceID),
		Sequence: sequence,
	}
	return dropped
}

func normalizeDetailedPort(port DetailedPort) DetailedPort {
	port.Protocol = strings.ToLower(port.Protocol)
	return port
}

func normalizeDetailedSource(source DetailedSource) DetailedSource {
	source.Target = strings.TrimSpace(source.Target)
	source.PortRange = strings.TrimSpace(source.PortRange)
	source.Protocol = strings.ToLower(strings.TrimSpace(source.Protocol))
	return source
}

func detailedSourceFromTargetKey(targetKey string) DetailedSource {
	target, portRange, protocol := parseTargetKey(targetKey)
	return normalizeDetailedSource(DetailedSource{
		Target:    target,
		PortRange: portRange,
		Protocol:  protocol,
	})
}

func sortDetailedPorts(ports []DetailedPort) {
	sort.Slice(ports, func(i, j int) bool {
		left, right := ports[i], ports[j]
		if left.Alias != right.Alias {
			return left.Alias < right.Alias
		}
		if left.IP != right.IP {
			return left.IP < right.IP
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		return left.Protocol < right.Protocol
	})
}

func (mc *Collector) removeDetailedOwnerLocked(port DetailedPort, sourceID DetailedSource) {
	series := mc.detailedPorts[port]
	if series == nil {
		return
	}
	delete(series.Owners, sourceID)
	if source := mc.detailedPortSources[sourceID]; source != nil {
		delete(source.Ports, port)
	}
	if len(series.Owners) == 0 {
		deleteDetailedPortMetric(mc.portOpen, port)
		delete(mc.detailedPorts, port)
	}
}

func (mc *Collector) removeDetailedSourceLocked(sourceID DetailedSource) {
	source := mc.detailedPortSources[sourceID]
	if source == nil {
		return
	}
	for port := range source.Ports {
		series := mc.detailedPorts[port]
		if series == nil {
			continue
		}
		delete(series.Owners, sourceID)
		if len(series.Owners) == 0 {
			deleteDetailedPortMetric(mc.portOpen, port)
			delete(mc.detailedPorts, port)
		}
	}
	delete(mc.detailedPortSources, sourceID)
}

func (mc *Collector) removeDetailedSeriesLocked(port DetailedPort) {
	series := mc.detailedPorts[port]
	if series == nil {
		return
	}
	for sourceID := range series.Owners {
		if source := mc.detailedPortSources[sourceID]; source != nil {
			delete(source.Ports, port)
		}
	}
	deleteDetailedPortMetric(mc.portOpen, port)
	delete(mc.detailedPorts, port)
}

func (mc *Collector) enforceDetailedBudgetLocked(budget int) int {
	if budget <= 0 || len(mc.detailedPorts) <= budget {
		return 0
	}
	ports := make([]DetailedPort, 0, len(mc.detailedPorts))
	for port := range mc.detailedPorts {
		ports = append(ports, port)
	}
	sortDetailedPorts(ports)
	for _, port := range ports[budget:] {
		mc.removeDetailedSeriesLocked(port)
	}
	return len(ports) - budget
}

func normalizeDetailedSourceTTLRules(rules []DetailedSourceTTLRule) []DetailedSourceTTLRule {
	normalized := make([]DetailedSourceTTLRule, 0, len(rules))
	for _, rule := range rules {
		if rule.MinTTL <= 0 {
			continue
		}
		rule.Source = normalizeDetailedSource(rule.Source)
		if rule.Source == (DetailedSource{}) {
			continue
		}
		normalized = append(normalized, rule)
	}
	return normalized
}

func (mc *Collector) detailedSourceTTLLocked(source DetailedSource) time.Duration {
	var minimum time.Duration
	for _, rule := range mc.detailedSourceTTLs {
		if source.PortRange != rule.Source.PortRange || source.Protocol != rule.Source.Protocol {
			continue
		}
		if !detailTargetWithin(source.Target, rule.Source.Target) {
			continue
		}
		if rule.MinTTL > minimum {
			minimum = rule.MinTTL
		}
	}
	return minimum
}

func detailTargetWithin(target, parent string) bool {
	if target == parent {
		return true
	}
	childPrefix, childOK := detailTargetPrefix(target)
	parentPrefix, parentOK := detailTargetPrefix(parent)
	if !childOK || !parentOK || childPrefix.Addr().BitLen() != parentPrefix.Addr().BitLen() {
		return false
	}
	return childPrefix.Bits() >= parentPrefix.Bits() && parentPrefix.Contains(childPrefix.Addr())
}

func detailTargetPrefix(target string) (netip.Prefix, bool) {
	target = strings.TrimSpace(target)
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return prefix.Masked(), true
	}
	if address, err := netip.ParseAddr(target); err == nil {
		return netip.PrefixFrom(address, address.BitLen()), true
	}
	return netip.Prefix{}, false
}

func (mc *Collector) clearDetailedPortsLocked() {
	mc.portOpen.Reset()
	clear(mc.detailedPorts)
	clear(mc.detailedPortSources)
}

func setDetailedPortMetric(metric *prometheus.GaugeVec, port DetailedPort) {
	metric.WithLabelValues(port.Alias, port.IP, port.Port, port.Protocol).Set(1)
}

func deleteDetailedPortMetric(metric *prometheus.GaugeVec, port DetailedPort) {
	_ = metric.DeleteLabelValues(port.Alias, port.IP, port.Port, port.Protocol)
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
