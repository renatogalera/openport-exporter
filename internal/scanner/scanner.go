package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/big"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"golang.org/x/sync/semaphore"

	"github.com/renatogalera/openport-exporter/internal/allowlist"
	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	metricspkg "github.com/renatogalera/openport-exporter/internal/metrics"
	taskspkg "github.com/renatogalera/openport-exporter/internal/tasks"
)

// ScanTask represents a unit of work for scanning a target with specific parameters.
type ScanTask struct {
	Target    string
	PortRange string
	Protocol  string
	// Optional task orchestration
	TaskID                 string
	Module                 string
	MaxCIDRSizeOverride    int
	TimeoutOverrideSeconds int
	Attempts               int
	MaxAttempts            int
}

// ModuleLimiter controls per-module concurrency using semaphore.Weighted.
type ModuleLimiter struct {
	mu   sync.Mutex
	sems map[string]*semaphore.Weighted
	caps map[string]int
}

func NewModuleLimiter() *ModuleLimiter {
	return &ModuleLimiter{sems: make(map[string]*semaphore.Weighted), caps: make(map[string]int)}
}

// Ensure prepares a semaphore for a module with the given capacity.
func (ml *ModuleLimiter) Ensure(module string, capacity int) {
	if strings.TrimSpace(module) == "" {
		module = "default"
	}
	ml.mu.Lock()
	defer ml.mu.Unlock()
	if capacity <= 0 {
		delete(ml.sems, module)
		delete(ml.caps, module)
		return
	}
	if prev, ok := ml.caps[module]; !ok || prev != capacity {
		ml.sems[module] = semaphore.NewWeighted(int64(capacity))
		ml.caps[module] = capacity
	}
}

// Acquire acquires a single slot for the module, returning a release function.
func (ml *ModuleLimiter) Acquire(ctx context.Context, module string) func() {
	if strings.TrimSpace(module) == "" {
		module = "default"
	}
	ml.mu.Lock()
	sem := ml.sems[module]
	ml.mu.Unlock()
	if sem == nil {
		return func() {}
	}
	_ = sem.Acquire(ctx, 1)
	return func() { sem.Release(1) }
}

// EnqueueScanTask splits a CIDR into subnets (bounded by maxCIDRSize) and enqueues each as a task.
func EnqueueScanTask(
	ctx context.Context,
	taskQueue chan ScanTask,
	target, portRange, protocol string,
	maxCIDRSize int,
) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context done: %w", err)
	}
	subnets, err := splitIntoSubnets(target, maxCIDRSize)
	if err != nil {
		return fmt.Errorf("failed to split target into subnets: %w", err)
	}
	for _, subnet := range subnets {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context done: %w", err)
		}
		select {
		case taskQueue <- ScanTask{Target: subnet, PortRange: portRange, Protocol: protocol}:
			// ok
		default:
			return fmt.Errorf("worker queue is full")
		}
	}
	return nil
}

// StartWorkers runs N workers to consume ScanTasks with a bounded concurrency semaphore.
// Each task runs with its own timeout from cfg.Scanning.Timeout.
// ReEnqueueFunc re-enqueues a task with a priority hint. Returns true if accepted.
type ReEnqueueFunc func(task ScanTask, priority string) bool

func StartWorkers(
	ctx context.Context,
	workerCount int,
	taskQueue chan ScanTask,
	mgr *cfgpkg.Manager,
	metricsCollector *metricspkg.Collector,
	log *slog.Logger,
	taskMgr *taskspkg.Manager,
	reEnqueue ReEnqueueFunc,
) {
	semaphore := make(chan struct{}, workerCount)
	modLimiter := NewModuleLimiter()
	for i := 0; i < workerCount; i++ {
		go worker(ctx, taskQueue, mgr, semaphore, metricsCollector, log, taskMgr, reEnqueue, modLimiter)
	}
}

// worker processes scan tasks from the queue with semaphore-controlled concurrency.
func worker(
	ctx context.Context,
	taskQueue chan ScanTask,
	mgr *cfgpkg.Manager,
	semaphore chan struct{},
	metricsCollector *metricspkg.Collector,
	log *slog.Logger,
	taskMgr *taskspkg.Manager,
	reEnqueue ReEnqueueFunc,
	modLimiter *ModuleLimiter,
) {
	for task := range taskQueue {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Acquire semaphore token to bound concurrency
		semaphore <- struct{}{}

		// Run the scan synchronously in this goroutine
		log.Debug(
			"Worker picked up a task",
			"target",
			task.Target,
			"portRange",
			task.PortRange,
			"protocol",
			task.Protocol,
		)
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Error("Recovered from panic", "task", task, "panic", r)
				}
			}()
			// Snapshot config for this task
			cfg := mgr.Get()
			// Apply module overrides if present
			if strings.TrimSpace(task.Module) != "" {
				if mod, ok := cfg.Modules[task.Module]; ok {
					ApplyModuleToConfig(&cfg, &mod)
				}
			}
			// Apply protocol override for this task
			if strings.EqualFold(task.Protocol, "udp") {
				cfg.Scanning.UDPScan = true
			} else if strings.EqualFold(task.Protocol, "tcp") {
				cfg.Scanning.UDPScan = false
			}
			// Apply MaxCIDR override
			if task.MaxCIDRSizeOverride > 0 {
				cfg.Scanning.MaxCIDRSize = task.MaxCIDRSizeOverride
			}
			// Per-module concurrency limit
			limit := 0
			if cfg.Scheduler != nil && cfg.Scheduler.ModuleLimits != nil {
				if v, ok := cfg.Scheduler.ModuleLimits[strings.TrimSpace(task.Module)]; ok {
					limit = v
				}
				if limit <= 0 {
					if v, ok := cfg.Scheduler.ModuleLimits["default"]; ok {
						limit = v
					}
				}
			}
			allowCache := mgr.GetAllowlistCache()
			timeout := time.Duration(cfg.Scanning.Timeout) * time.Second
			if task.TimeoutOverrideSeconds > 0 {
				timeout = time.Duration(task.TimeoutOverrideSeconds) * time.Second
			}
			scanCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			modLimiter.Ensure(task.Module, limit)
			releaseMod := modLimiter.Acquire(scanCtx, task.Module)
			defer releaseMod()
			// If this task is a part of a composed background API task, mark start
			if task.TaskID != "" && taskMgr != nil {
				taskMgr.Start(task.TaskID, cancel)
				metricsCollector.SetSchedulerRunning(taskMgr.RunningCount())
			}
			openCount, up, down, dur, err := scanTarget(
				scanCtx,
				task,
				&cfg,
				metricsCollector,
				log,
				allowCache,
			)
			if err != nil {
				log.Error(
					"Scan failed",
					"target",
					task.Target,
					"portRange",
					task.PortRange,
					"protocol",
					task.Protocol,
					"error",
					err,
				)
			}
			if task.TaskID != "" && taskMgr != nil {
				if err != nil && task.Attempts < task.MaxAttempts && reEnqueue != nil {
					// Backoff & retry once (or configured attempts)
					next := task
					next.Attempts++
					// schedule re-enqueue after short jitter
					go func(retryTask ScanTask) {
						time.Sleep(time.Duration(250+rand.IntN(500)) * time.Millisecond)
						_ = reEnqueue(retryTask, "low")
					}(next)
				} else {
					done, outcome, elapsed := taskMgr.SubtaskDone(task.TaskID, up, down, openCount, err)
					metricsCollector.SetSchedulerRunning(taskMgr.RunningCount())
					if done {
						mod := task.Module
						if strings.TrimSpace(mod) == "" {
							mod = "default"
						}
						if outcome == "" {
							outcome = "success"
						}
						metricsCollector.IncTasksCompleted(mod, outcome)
						if elapsed > 0 {
							metricsCollector.ObserveTaskDuration(mod, elapsed)
						}
					}
				}
			}
			// Update scheduler running metric approximate via semaphore occupancy later (optional)
			_ = dur
		}()

		metricsCollector.UpdateTaskQueueSize(len(taskQueue))
		// Release semaphore token
		<-semaphore
	}
}

// scanTarget executes a single scan task and updates metrics with the results.
// hookable run function for tests
var runNmapFn = runNmapScan

func scanTarget(
	ctx context.Context,
	task ScanTask,
	cfg *cfgpkg.Config,
	metricsCollector *metricspkg.Collector,
	log *slog.Logger,
	allowCache *allowlist.Cache,
) (int, int, int, float64, error) {
	scannerInstance, err := createNmapScanner(task, cfg, ctx)
	if err != nil {
		metricsCollector.IncrementScanFailure(task.Target, task.PortRange, task.Protocol, "scanner_creation")
		return 0, 0, 0, 0, fmt.Errorf("failed to create Nmap scanner: %w", err)
	}

	startTime := time.Now()
	result, warnings, err := runNmapFn(ctx, scannerInstance, task, log)
	if err != nil {
		errorType := categorizeError(err)
		metricsCollector.IncrementScanFailure(task.Target, task.PortRange, task.Protocol, errorType)
		if errorType == "timeout" {
			metricsCollector.IncrementScanTimeout(task.Target, task.PortRange, task.Protocol)
		}
		return 0, 0, 0, 0, fmt.Errorf("failed to run Nmap scan: %w", err)
	}
	metricsCollector.IncrementScanSuccess(task.Target, task.PortRange, task.Protocol)
	metricsCollector.SetLastScanTimestamp(task.Target, task.PortRange, task.Protocol, time.Now())
	if warnings != nil && len(*warnings) > 0 {
		log.Warn("Scan warnings", "warnings", *warnings)
	}

	duration := time.Since(startTime).Seconds()
	if cfg.Scanning.DurationMetrics {
		metricsCollector.ObserveScanDuration(task.Target, task.PortRange, task.Protocol, duration)
		metricsCollector.GetScanDurationHistogram().WithLabelValues(
			task.Target,
			task.PortRange,
			task.Protocol,
		).Observe(
			duration,
		)
	}

	newResults, hostsUp, hostsDown := processNmapResults(result, task, log)

	// Aggregate metrics per (target,port_range,protocol)
	metricsCollector.UpdateMetrics(createTargetKey(task.Target, task.PortRange, task.Protocol), newResults)
	metricsCollector.UpdateHostCounts(task.Target, task.PortRange, task.Protocol, hostsUp, hostsDown)

	// Background details (allowlisted & bounded)
	if cfg.BackgroundDetails != nil && cfg.BackgroundDetails.Enabled && allowCache != nil {
		seriesBudget := cfg.BackgroundDetails.SeriesBudget
		for portKey := range newResults {
			ip, port, proto := parseK(portKey) // "ip:port/proto"
			if alias, ok := allowCache.Lookup(ip, port, proto); ok {
				aliasLabel, ipLabel := buildDetailLabels(cfg.BackgroundDetails, alias, ip)
				// Atomically check budget and add metric to prevent race conditions
				if !metricsCollector.SetDetailedPortOpenWithBudget(
					aliasLabel,
					ipLabel,
					port,
					strings.ToLower(proto),
					seriesBudget,
				) {
					metricsCollector.IncrementDroppedSeries()
				}
			}
		}
	}

	return len(newResults), hostsUp, hostsDown, duration, nil
}

// buildDetailLabels centraliza a lógica de construção de labels para detalhes de portas.
func buildDetailLabels(cfg *cfgpkg.BackgroundDetailsConfig, foundAlias, foundIP string) (alias, ip string) {
	// IP label
	if cfg.IncludeIP == nil || *cfg.IncludeIP {
		ip = foundIP
	} else {
		ip = ""
	}
	// Alias label
	if cfg.IncludeAlias {
		if foundAlias != "" {
			alias = foundAlias
		} else {
			alias = ip
		}
	} else {
		alias = ""
	}
	return alias, ip
}

// parseK parses a port key in format "host:port/proto" and returns ip, port, protocol.
func parseK(k string) (ip, port, proto string) {
	proto = "tcp"
	if i := strings.LastIndexByte(k, '/'); i >= 0 {
		proto = k[i+1:]
		k = k[:i]
	}
	if host, p, err := net.SplitHostPort(k); err == nil {
		return host, p, proto
	}
	// Fallback parsing
	if i := strings.LastIndex(k, ":"); i > 0 && i < len(k)-1 {
		return k[:i], k[i+1:], proto
	}
	return k, "", proto
}

// scanResult holds the result of an Nmap scan operation.
type scanResult struct {
	result   *nmap.Run
	warnings *[]string
	err      error
}

// runNmapScan executes an Nmap scan with context cancellation support.
func runNmapScan(
	ctx context.Context,
	scanner *nmap.Scanner,
	task ScanTask,
	log *slog.Logger,
) (*nmap.Run, *[]string, error) {
	resultCh := make(chan scanResult, 1)
	go func() {
		result, warnings, err := scanner.Run()
		resultCh <- scanResult{
			result:   result,
			warnings: warnings,
			err:      err,
		}
	}()
	select {
	case <-ctx.Done():
		log.Warn("nmap scan timed out", "target", task.Target)
		return nil, nil, fmt.Errorf("nmap scan timed out: %w", ctx.Err())
	case res := <-resultCh:
		if res.err != nil {
			return nil, nil, fmt.Errorf("unable to run Nmap scan: %w", res.err)
		}
		return res.result, res.warnings, nil
	}
}

// processNmapResults processes Nmap scan results and returns open ports, host counts.
func processNmapResults(result *nmap.Run, task ScanTask, log *slog.Logger) (map[string]struct{}, int, int) {
	newResults := make(map[string]struct{})
	hostsUp := 0
	hostsDown := 0
	for _, host := range result.Hosts {
		if host.Status.State == "up" {
			hostsUp++
		} else {
			hostsDown++
		}
		if len(host.Ports) > 0 && len(host.Addresses) > 0 {
			for _, port := range host.Ports {
				if port.State.State == "open" {
					// Store as "ip:port/proto" using JoinHostPort to handle IPv6 correctly
					ipStr := host.Addresses[0].String()
					hostPort := net.JoinHostPort(ipStr, strconv.Itoa(int(port.ID)))
					portKey := fmt.Sprintf("%s/%s", hostPort, strings.ToLower(task.Protocol))
					newResults[portKey] = struct{}{}
					log.Debug(
						"Open port found",
						"ip",
						ipStr,
						"port",
						port.ID,
						"protocol",
						task.Protocol,
					)
				}
			}
		}
	}
	return newResults, hostsUp, hostsDown
}

// RunImmediateScan executes a synchronous scan for an ad-hoc target/ports/protocol,
// splitting large CIDRs as needed (bounded by maxCIDRSizeOverride). It returns the set
// of "ip:port/proto" found open, the total hosts up/down observed, the total duration
// in seconds, and an error if any subnet scan fails.
func RunImmediateScan(
	ctx context.Context,
	cfg *cfgpkg.Config,
	target, portRange, protocol string,
	maxCIDRSizeOverride int,
	log *slog.Logger,
) (map[string]struct{}, int, int, float64, error) {
	// Work on a local copy to avoid mutating global config inadvertently.
	localCfg := *cfg

	// Ensure exclusive protocol behavior: use UDP scan iff protocol == "udp".
	if strings.ToLower(protocol) == "udp" {
		localCfg.Scanning.UDPScan = true
	} else {
		localCfg.Scanning.UDPScan = false
	}

	// Allow caller to tighten the subnet split size for probes.
	if maxCIDRSizeOverride > 0 {
		localCfg.Scanning.MaxCIDRSize = maxCIDRSizeOverride
	}

	start := time.Now()
	results := make(map[string]struct{})
	hostsUpTotal := 0
	hostsDownTotal := 0

	subs, err := splitIntoSubnets(target, localCfg.Scanning.MaxCIDRSize)
	if err != nil {
		return nil, 0, 0, 0, err
	}

	for _, subnet := range subs {
		select {
		case <-ctx.Done():
			return nil, 0, 0, 0, fmt.Errorf("context done: %w", ctx.Err())
		default:
		}

		t := ScanTask{Target: subnet, PortRange: portRange, Protocol: protocol}

		sc, err := createNmapScanner(t, &localCfg, ctx)
		if err != nil {
			return nil, 0, 0, 0, fmt.Errorf("failed to create scanner: %w", err)
		}

		run, warnings, err := runNmapScan(ctx, sc, t, log)
		if err != nil {
			return nil, 0, 0, 0, err
		}
		if warnings != nil && len(*warnings) > 0 {
			log.Warn("probe warnings", "warnings", *warnings)
		}

		r, up, down := processNmapResults(run, t, log)
		for k := range r {
			results[k] = struct{}{}
		}
		hostsUpTotal += up
		hostsDownTotal += down
	}

	dur := time.Since(start).Seconds()
	return results, hostsUpTotal, hostsDownTotal, dur, nil
}

// createNmapScanner builds an Nmap scanner with exclusive TCP or UDP mode (never both).
func createNmapScanner(task ScanTask, cfg *cfgpkg.Config, ctx context.Context) (*nmap.Scanner, error) {
	scannerOptions := []nmap.Option{
		nmap.WithTargets(task.Target),
		nmap.WithPorts(task.PortRange),
	}
	// Exclusive protocol selection
	if cfg.Scanning.UDPScan || strings.ToLower(task.Protocol) == "udp" {
		scannerOptions = append(scannerOptions, nmap.WithUDPScan())
	} else {
		if cfg.UseSYNScanEnabled() {
			scannerOptions = append(scannerOptions, nmap.WithSYNScan())
		} else {
			scannerOptions = append(scannerOptions, nmap.WithConnectScan())
		}
	}

	// Nmap Performance Tuning Options
	if cfg.Scanning.MinRate > 0 {
		scannerOptions = append(scannerOptions, nmap.WithMinRate(cfg.Scanning.MinRate))
	}
	if cfg.Scanning.MaxRate > 0 {
		scannerOptions = append(scannerOptions, nmap.WithMaxRate(cfg.Scanning.MaxRate))
	}
	if cfg.Scanning.MinParallelism > 0 {
		scannerOptions = append(scannerOptions, nmap.WithMinParallelism(cfg.Scanning.MinParallelism))
	}
	if cfg.Scanning.MaxRetries > 0 {
		scannerOptions = append(scannerOptions, nmap.WithMaxRetries(cfg.Scanning.MaxRetries))
	}
	if cfg.Scanning.HostTimeout > 0 {
		scannerOptions = append(
			scannerOptions,
			nmap.WithHostTimeout(time.Duration(cfg.Scanning.HostTimeout)*time.Second),
		)
	}
	if cfg.Scanning.ScanDelay > 0 {
		scannerOptions = append(
			scannerOptions,
			nmap.WithScanDelay(time.Duration(cfg.Scanning.ScanDelay)*time.Millisecond),
		)
	}
	if cfg.Scanning.MaxScanDelay > 0 {
		scannerOptions = append(
			scannerOptions,
			nmap.WithMaxScanDelay(time.Duration(cfg.Scanning.MaxScanDelay)*time.Millisecond),
		)
	}
	if cfg.Scanning.DisableDNSResolution {
		scannerOptions = append(scannerOptions, nmap.WithDisabledDNSResolution())
	}
	if cfg.Scanning.InitialRttTimeout > 0 {
		scannerOptions = append(
			scannerOptions,
			nmap.WithInitialRTTTimeout(time.Duration(cfg.Scanning.InitialRttTimeout)*time.Millisecond),
		)
	}
	if cfg.Scanning.MaxRttTimeout > 0 {
		scannerOptions = append(
			scannerOptions,
			nmap.WithMaxRTTTimeout(time.Duration(cfg.Scanning.MaxRttTimeout)*time.Millisecond),
		)
	}
	if cfg.Scanning.MinRttTimeout > 0 {
		scannerOptions = append(
			scannerOptions,
			nmap.WithMinRTTTimeout(time.Duration(cfg.Scanning.MinRttTimeout)*time.Millisecond),
		)
	}
	if cfg.Scanning.DisableHostDiscovery {
		scannerOptions = append(scannerOptions, nmap.WithSkipHostDiscovery())
	}

	sc, err := nmap.NewScanner(ctx, scannerOptions...)
	if err != nil {
		return nil, fmt.Errorf("create nmap scanner: %w", err)
	}
	return sc, nil
}

// splitIntoSubnets splits a target (IP or CIDR) into smaller subnets based on maxCIDRSize.
func splitIntoSubnets(target string, maxCIDRSize int) ([]string, error) {
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}, nil
	}
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %s", target)
	}
	ones, bits := ipNet.Mask.Size()
	switch bits {
	case 32:
		return splitIPv4Subnet(target, ones, maxCIDRSize)
	case 128:
		return splitIPv6Subnet(target, ones, maxCIDRSize)
	default:
		return nil, fmt.Errorf("unsupported IP version for target: %s", target)
	}
}

// SplitIntoSubnets exposes subnet splitting for external callers (HTTP tasks API)
func SplitIntoSubnets(target string, maxCIDRSize int) ([]string, error) {
	return splitIntoSubnets(target, maxCIDRSize)
}

// splitIPv4Subnet splits an IPv4 CIDR into smaller subnets of maxCIDRSize.
func splitIPv4Subnet(target string, ones, maxCIDRSize int) ([]string, error) {
	if ones >= maxCIDRSize {
		return []string{target}, nil
	}
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPv4 subnet: %w", err)
	}
	baseIP := ipNet.IP.Mask(ipNet.Mask).To4()
	if baseIP == nil {
		return nil, fmt.Errorf("invalid IPv4 network: %s", target)
	}
	diff := maxCIDRSize - ones
	if diff < 0 || diff > 32 {
		return nil, fmt.Errorf("invalid CIDR split: ones=%d max=%d", ones, maxCIDRSize)
	}
	numSubnets := 1 << diff
	step := uint32(1) << uint32(32-maxCIDRSize)
	base := binary.BigEndian.Uint32(baseIP)
	result := make([]string, 0, numSubnets)
	for i := 0; i < numSubnets; i++ {
		addr := base + uint32(i)*step
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], addr)
		ip := net.IP(buf[:])
		result = append(result, fmt.Sprintf("%s/%d", ip.String(), maxCIDRSize))
	}
	return result, nil
}

// splitIPv6Subnet splits an IPv6 CIDR into smaller subnets of maxCIDRSize.
func splitIPv6Subnet(target string, ones, maxCIDRSize int) ([]string, error) {
	if ones >= maxCIDRSize {
		return []string{target}, nil
	}
	if maxCIDRSize > 128 || maxCIDRSize < ones {
		return nil, fmt.Errorf("invalid mask length for IPv6 subnetting: %d", maxCIDRSize)
	}
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPv6 subnet: %w", err)
	}
	baseIP := ipNet.IP.Mask(ipNet.Mask).To16()
	if baseIP == nil {
		return nil, fmt.Errorf("invalid IPv6 network: %s", target)
	}
	diff := maxCIDRSize - ones
	if diff < 0 || diff > 128 {
		return nil, fmt.Errorf("invalid CIDR split: ones=%d max=%d", ones, maxCIDRSize)
	}
	numSubnets := new(big.Int).Lsh(big.NewInt(1), uint(diff))
	step := new(big.Int).Lsh(big.NewInt(1), uint(128-maxCIDRSize))
	base := new(big.Int).SetBytes(baseIP)
	cur := new(big.Int).Set(base)
	result := make([]string, 0)
	for i := new(big.Int).SetInt64(0); i.Cmp(numSubnets) < 0; i.Add(i, big.NewInt(1)) {
		b := cur.Bytes()
		ip := make([]byte, 16)
		if len(b) > 16 {
			copy(ip, b[len(b)-16:])
		} else {
			copy(ip[16-len(b):], b)
		}
		result = append(result, fmt.Sprintf("%s/%d", net.IP(ip).String(), maxCIDRSize))
		cur.Add(cur, step)
	}
	return result, nil
}

// createTargetKey includes protocol to avoid mixing TCP and UDP into the same state bucket.
func createTargetKey(ipRange, portRange, proto string) string {
	return ipRange + "_" + portRange + "_" + strings.ToLower(proto)
}

// CreateTargetKeyFor exports the key builder for scheduler usage.
func CreateTargetKeyFor(ipRange, portRange, proto string) string {
	return createTargetKey(ipRange, portRange, proto)
}

// categorizeError categorizes scan errors into types for metrics labeling.
func categorizeError(err error) string {
	if err != nil {
		le := strings.ToLower(err.Error())
		if strings.Contains(le, "timeout") {
			return "timeout"
		}
		if strings.Contains(le, "permission") {
			return "permission"
		}
	}
	return "other"
}

// ApplyModuleToConfig overrides scanning fields using a module preset
func ApplyModuleToConfig(cfg *cfgpkg.Config, mod *cfgpkg.Module) {
	if mod == nil {
		return
	}
	sc := &cfg.Scanning
	if mod.UseSYNScan != nil {
		sc.UseSYNScan = mod.UseSYNScan
	}
	if mod.MinRate != nil {
		sc.MinRate = *mod.MinRate
	}
	if mod.MaxRate != nil {
		sc.MaxRate = *mod.MaxRate
	}
	if mod.MinParallelism != nil {
		sc.MinParallelism = *mod.MinParallelism
	}
	if mod.MaxRetries != nil {
		sc.MaxRetries = *mod.MaxRetries
	}
	if mod.HostTimeout != nil {
		sc.HostTimeout = *mod.HostTimeout
	}
	if mod.ScanDelay != nil {
		sc.ScanDelay = *mod.ScanDelay
	}
	if mod.MaxScanDelay != nil {
		sc.MaxScanDelay = *mod.MaxScanDelay
	}
	if mod.InitialRttTimeout != nil {
		sc.InitialRttTimeout = *mod.InitialRttTimeout
	}
	if mod.MaxRttTimeout != nil {
		sc.MaxRttTimeout = *mod.MaxRttTimeout
	}
	if mod.MinRttTimeout != nil {
		sc.MinRttTimeout = *mod.MinRttTimeout
	}
	if mod.DisableHostDiscovery != nil {
		sc.DisableHostDiscovery = *mod.DisableHostDiscovery
	}
}
