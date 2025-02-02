package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"openport-exporter/config"
	"openport-exporter/metrics"

	"github.com/Ullaakut/nmap"
	"github.com/c-robinson/iplib"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// ScanTask represents a scanning task.
type ScanTask struct {
	Target    string
	PortRange string
	Protocol  string
}

// Response represents an HTTP response.
type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// EnqueueScanTask splits the target into subnets (if CIDR) and enqueues them as tasks.
func EnqueueScanTask(ctx context.Context, taskQueue chan ScanTask, target, portRange, protocol string, maxCIDRSize int) error {
	subnets, err := splitIntoSubnets(target, maxCIDRSize)
	if err != nil {
		return fmt.Errorf("failed to split target into subnets: %w", err)
	}

	for _, subnet := range subnets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case taskQueue <- ScanTask{
			Target:    subnet,
			PortRange: portRange,
			Protocol:  protocol,
		}:
			// The queue size is updated in the worker after consumption
		}
	}

	return nil
}

// StartWorkers starts worker goroutines to process scan tasks concurrently.
func StartWorkers(ctx context.Context, workerCount int, taskQueue chan ScanTask, cfg *config.Config, metricsCollector *metrics.MetricsCollector) {
	semaphore := make(chan struct{}, workerCount)
	for i := 0; i < workerCount; i++ {
		go worker(ctx, taskQueue, cfg, semaphore, metricsCollector)
	}
}

// HandleQuery handles HTTP queries to initiate scans.
func HandleQuery(cfg *config.Config, rateLimiter *rate.Limiter, log *logrus.Logger, taskQueue chan ScanTask, metricsCollector *metrics.MetricsCollector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logRequestReceived(r, log)

		if !checkRateLimit(ctx, rateLimiter, w, log) {
			return
		}

		ipRange, portRange, protocol, err := parseQueryParams(r)
		if err != nil {
			handleBadRequest(w, log, err)
			return
		}

		targetKey := createTargetKey(ipRange, portRange)

		if !metricsCollector.CanScan(targetKey, cfg.GetScanIntervalDuration()) {
			log.WithFields(logrus.Fields{"target": targetKey}).Info("Skipping scan, interval not reached")
			jsonResponse(w, Response{Status: "skipped", Message: "Scan interval not reached"}, http.StatusAccepted)
			return
		}

		if err := EnqueueScanTask(ctx, taskQueue, ipRange, portRange, protocol, cfg.Scanning.MaxCIDRSize); err != nil {
			handleEnqueueError(w, log, err, ipRange, portRange, protocol)
			return
		}

		metricsCollector.RegisterScan(targetKey)
		handleSuccessResponse(w, log, ipRange, portRange, protocol)
	}
}

// ------------------- PRIVATE WORKER & SCAN LOGIC -------------------

func worker(ctx context.Context, taskQueue chan ScanTask, cfg *config.Config,
	semaphore chan struct{}, metricsCollector *metrics.MetricsCollector) {

	for {
		select {
		case <-ctx.Done():
			return
		case task := <-taskQueue:
			semaphore <- struct{}{}
			go func(task ScanTask) {
				defer func() { <-semaphore }()

				logrus.WithFields(logrus.Fields{
					"target":    task.Target,
					"portRange": task.PortRange,
				}).Debug("Worker picked up a task")

				scanCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Scanning.Timeout)*time.Second)
				defer cancel()

				if err := scanTarget(scanCtx, task, cfg, metricsCollector); err != nil {
					logrus.WithFields(logrus.Fields{
						"target":    task.Target,
						"portRange": task.PortRange,
						"error":     err,
					}).Error("Scan failed")
				}
				metricsCollector.UpdateTaskQueueSize(len(taskQueue))
			}(task)
		}
	}
}

func scanTarget(ctx context.Context, task ScanTask, cfg *config.Config, metricsCollector *metrics.MetricsCollector) error {
	scanner, err := createNmapScanner(task, cfg, ctx)
	if err != nil {
		return fmt.Errorf("failed to create Nmap scanner: %w", err)
	}

	startTime := time.Now()
	result, warnings, err := runNmapScan(ctx, scanner, task, metricsCollector)
	if err != nil {
		return fmt.Errorf("failed to run Nmap scan: %w", err)
	}

	if warnings != nil {
		logrus.Warn(warnings)
	}

	duration := time.Since(startTime).Seconds()
	newResults := processNmapResults(result, task)

	updateMetrics(task, cfg, duration, newResults, metricsCollector)
	return nil
}

func createNmapScanner(task ScanTask, cfg *config.Config, ctx context.Context) (*nmap.Scanner, error) {
	scannerOptions := []func(*nmap.Scanner){
		nmap.WithTargets(task.Target),
		nmap.WithPorts(task.PortRange),
		nmap.WithContext(ctx),
		nmap.WithMinRate(cfg.Scanning.MinRate),
		nmap.WithMinParallelism(cfg.Scanning.MinParallelism),
		nmap.WithSYNScan(),
	}

	if cfg.Scanning.DisableDNSResolution {
		scannerOptions = append(scannerOptions, nmap.WithDisabledDNSResolution())
	}

	return nmap.NewScanner(scannerOptions...)
}

func runNmapScan(ctx context.Context, scanner *nmap.Scanner, task ScanTask, metricsCollector *metrics.MetricsCollector) (*nmap.Run, []string, error) {
	resultChan := make(chan *nmap.Run, 1)
	warningsChan := make(chan []string, 1)
	errChan := make(chan error, 1)

	go func() {
		result, warnings, err := scanner.Run()
		resultChan <- result
		warningsChan <- warnings
		errChan <- err
	}()

	select {
	case <-ctx.Done():
		metricsCollector.IncrementScanTimeout(task.Target, task.PortRange, task.Protocol)
		return nil, nil, fmt.Errorf("nmap scan timed out: %w", ctx.Err())
	case err := <-errChan:
		if err != nil {
			return nil, nil, fmt.Errorf("unable to run Nmap scan: %w", err)
		}
		return <-resultChan, <-warningsChan, nil
	}
}

func processNmapResults(result *nmap.Run, task ScanTask) map[string]struct{} {
	newResults := make(map[string]struct{})
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		for _, port := range host.Ports {
			if port.State.State == "open" {
				portKey := fmt.Sprintf("%s:%d", host.Addresses[0], port.ID)
				newResults[portKey] = struct{}{}
				logrus.WithFields(logrus.Fields{
					"ip":       host.Addresses[0],
					"port":     port.ID,
					"protocol": task.Protocol,
				}).Debug("Open port found")
			}
		}
	}
	return newResults
}

func updateMetrics(task ScanTask, cfg *config.Config, duration float64, newResults map[string]struct{}, metricsCollector *metrics.MetricsCollector) {
	targetKey := task.Target + "_" + task.PortRange
	if cfg.Scanning.DurationMetrics {
		metricsCollector.ObserveScanDuration(task.Target, task.PortRange, task.Protocol, duration)
	}
	metricsCollector.UpdateMetrics(targetKey, newResults)
}

// ------------------- PRIVATE HELPERS -------------------

// splitIntoSubnets splits a large CIDR into smaller subnets based on maxCIDRSize.
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

	net4 := iplib.Net4FromStr(target)
	subnets4, err := net4.Subnet(maxCIDRSize)
	if err != nil {
		return nil, fmt.Errorf("failed to split IPv4 subnet: %w", err)
	}

	result := make([]string, len(subnets4))
	for i, subnet := range subnets4 {
		result[i] = subnet.String()
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

	net6 := iplib.Net6FromStr(target)
	subnets6, err := net6.Subnet(maxCIDRSize, 128)
	if err != nil {
		return nil, fmt.Errorf("failed to split IPv6 subnet: %w", err)
	}

	result := make([]string, len(subnets6))
	for i, subnet := range subnets6 {
		result[i] = subnet.String()
	}
	return result, nil
}

// createTargetKey composes the target key used by metrics to ensure uniqueness.
func createTargetKey(ipRange, portRange string) string {
	return ipRange + "_" + portRange
}

func logRequestReceived(r *http.Request, log *logrus.Logger) {
	log.WithFields(logrus.Fields{
		"path": r.URL.Path,
	}).Info("Received query request")
}

func checkRateLimit(ctx context.Context, rateLimiter *rate.Limiter, w http.ResponseWriter, log *logrus.Logger) bool {
	if err := rateLimiter.Wait(ctx); err != nil {
		log.Warn("Too many requests")
		jsonResponse(w, Response{Status: "error", Message: "Too Many Requests"}, http.StatusTooManyRequests)
		return false
	}
	return true
}

func parseQueryParams(r *http.Request) (string, string, string, error) {
	ipRange := r.URL.Query().Get("ip")
	portRange := r.URL.Query().Get("ports")
	protocol := r.URL.Query().Get("protocol")

	if ipRange == "" || portRange == "" {
		return "", "", "", fmt.Errorf("missing required parameters 'ip' and 'ports'")
	}
	if protocol == "" {
		protocol = "tcp"
	}
	return ipRange, portRange, protocol, nil
}

func handleBadRequest(w http.ResponseWriter, log *logrus.Logger, err error) {
	log.Warn(err)
	jsonResponse(w, Response{
		Status:  "error",
		Message: "Missing required parameters",
		Details: err.Error(),
	}, http.StatusBadRequest)
}

func handleEnqueueError(w http.ResponseWriter, log *logrus.Logger, err error, ipRange, portRange, protocol string) {
	log.WithFields(logrus.Fields{
		"ipRange":   ipRange,
		"portRange": portRange,
		"protocol":  protocol,
		"error":     err,
	}).Warn("Failed to enqueue scan")
	jsonResponse(w, Response{Status: "error", Message: err.Error()}, http.StatusInternalServerError)
}

func handleSuccessResponse(w http.ResponseWriter, log *logrus.Logger, ipRange, portRange, protocol string) {
	log.WithFields(logrus.Fields{
		"ipRange":   ipRange,
		"portRange": portRange,
		"protocol":  protocol,
	}).Info("Scan enqueued successfully")
	jsonResponse(w, Response{Status: "success", Message: "Scan enqueued successfully"}, http.StatusOK)
}

func jsonResponse(w http.ResponseWriter, response Response, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(response)
}
