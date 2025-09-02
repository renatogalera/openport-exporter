package scanner

import (
    "context"
    "encoding/binary"
    "fmt"
    "log/slog"
    "math/big"
    "net"
    "strconv"
    "strings"
    "time"

	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	metricspkg "github.com/renatogalera/openport-exporter/internal/metrics"

	"github.com/Ullaakut/nmap/v3"
)

type ScanTask struct {
	Target    string
	PortRange string
	Protocol  string
}

// EnqueueScanTask splits a CIDR into subnets (bounded by maxCIDRSize) and enqueues each as a task.
func EnqueueScanTask(ctx context.Context, taskQueue chan ScanTask, target, portRange, protocol string, maxCIDRSize int) error {
	subnets, err := splitIntoSubnets(target, maxCIDRSize)
	if err != nil {
		return fmt.Errorf("failed to split target into subnets: %w", err)
	}
	for _, subnet := range subnets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			taskQueue <- ScanTask{
				Target:    subnet,
				PortRange: portRange,
				Protocol:  protocol,
			}
		}
	}
	return nil
}

// StartWorkers runs N workers to consume ScanTasks with a bounded concurrency semaphore.
// Each task runs with its own timeout from cfg.Scanning.Timeout.
func StartWorkers(ctx context.Context, workerCount int, taskQueue chan ScanTask, cfg *cfgpkg.Config, metricsCollector *metricspkg.MetricsCollector, log *slog.Logger) {
	semaphore := make(chan struct{}, workerCount)
	for i := 0; i < workerCount; i++ {
		go worker(ctx, taskQueue, cfg, semaphore, metricsCollector, log)
	}
}

func worker(ctx context.Context, taskQueue chan ScanTask, cfg *cfgpkg.Config, semaphore chan struct{}, metricsCollector *metricspkg.MetricsCollector, log *slog.Logger) {
    for task := range taskQueue {
        select {
        case <-ctx.Done():
            return
        default:
        }
        // Acquire semaphore token to bound concurrency
        semaphore <- struct{}{}

        // Run the scan synchronously in this goroutine
        log.Debug("Worker picked up a task", "target", task.Target, "portRange", task.PortRange, "protocol", task.Protocol)
        func() {
            defer func() {
                if r := recover(); r != nil {
                    log.Error("Recovered from panic", "task", task, "panic", r)
                }
            }()
            scanCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Scanning.Timeout)*time.Second)
            defer cancel()
            if err := scanTarget(scanCtx, task, cfg, metricsCollector, log); err != nil {
                log.Error("Scan failed", "target", task.Target, "portRange", task.PortRange, "protocol", task.Protocol, "error", err)
            }
        }()

        metricsCollector.UpdateTaskQueueSize(len(taskQueue))
        // Release semaphore token
        <-semaphore
    }
}

func scanTarget(ctx context.Context, task ScanTask, cfg *cfgpkg.Config, metricsCollector *metricspkg.MetricsCollector, log *slog.Logger) error {
	scannerInstance, err := createNmapScanner(task, cfg, ctx)
	if err != nil {
		metricsCollector.IncrementScanFailure(task.Target, task.PortRange, task.Protocol, "scanner_creation")
		return fmt.Errorf("failed to create Nmap scanner: %w", err)
	}

	startTime := time.Now()
	result, warnings, err := runNmapScan(ctx, scannerInstance, task, log)
	if err != nil {
		errorType := categorizeError(err)
		metricsCollector.IncrementScanFailure(task.Target, task.PortRange, task.Protocol, errorType)
		return fmt.Errorf("failed to run Nmap scan: %w", err)
	}
	metricsCollector.IncrementScanSuccess(task.Target, task.PortRange, task.Protocol)
	metricsCollector.SetLastScanTimestamp(task.Target, task.PortRange, task.Protocol, time.Now())
	if warnings != nil && len(*warnings) > 0 {
		log.Warn("Scan warnings", "warnings", *warnings)
	}

	duration := time.Since(startTime).Seconds()
	if cfg.Scanning.DurationMetrics {
		metricsCollector.ObserveScanDuration(task.Target, task.PortRange, task.Protocol, duration)
		metricsCollector.GetScanDurationHistogram().WithLabelValues(task.Target, task.PortRange, task.Protocol).Observe(duration)
	}

	newResults, hostsUp, hostsDown := processNmapResults(result, task, log)

	// Include protocol in the state key to avoid mixing TCP and UDP states.
	metricsCollector.UpdateMetrics(createTargetKey(task.Target, task.PortRange, task.Protocol), newResults)
	metricsCollector.UpdateHostCounts(task.Target, hostsUp, hostsDown)
	return nil
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
			return nil, 0, 0, 0, ctx.Err()
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

	// Tunables
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
		scannerOptions = append(scannerOptions, nmap.WithHostTimeout(time.Duration(cfg.Scanning.HostTimeout)*time.Second))
	}
	if cfg.Scanning.ScanDelay > 0 {
		scannerOptions = append(scannerOptions, nmap.WithScanDelay(time.Duration(cfg.Scanning.ScanDelay)*time.Millisecond))
	}
	if cfg.Scanning.MaxScanDelay > 0 {
		scannerOptions = append(scannerOptions, nmap.WithMaxScanDelay(time.Duration(cfg.Scanning.MaxScanDelay)*time.Millisecond))
	}
	if cfg.Scanning.DisableDNSResolution {
		scannerOptions = append(scannerOptions, nmap.WithDisabledDNSResolution())
	}
	if cfg.Scanning.InitialRttTimeout > 0 {
		scannerOptions = append(scannerOptions, nmap.WithInitialRTTTimeout(time.Duration(cfg.Scanning.InitialRttTimeout)*time.Millisecond))
	}
	if cfg.Scanning.MaxRttTimeout > 0 {
		scannerOptions = append(scannerOptions, nmap.WithMaxRTTTimeout(time.Duration(cfg.Scanning.MaxRttTimeout)*time.Millisecond))
	}
	if cfg.Scanning.MinRttTimeout > 0 {
		scannerOptions = append(scannerOptions, nmap.WithMinRTTTimeout(time.Duration(cfg.Scanning.MinRttTimeout)*time.Millisecond))
	}
	if cfg.Scanning.DisableHostDiscovery {
		scannerOptions = append(scannerOptions, nmap.WithSkipHostDiscovery())
	}

	return nmap.NewScanner(ctx, scannerOptions...)
}

type scanResult struct {
	result   *nmap.Run
	warnings *[]string
	err      error
}

func runNmapScan(ctx context.Context, scanner *nmap.Scanner, task ScanTask, log *slog.Logger) (*nmap.Run, *[]string, error) {
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
                    log.Debug("Open port found", "ip", ipStr, "port", port.ID, "protocol", task.Protocol)
                }
            }
		}
	}
	return newResults, hostsUp, hostsDown
}

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
