package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"openport-exporter/config"
	"openport-exporter/healthcheck"
	"openport-exporter/metrics"
	"openport-exporter/scanner"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// App is the main struct that orchestrates configuration, logging, metrics, and worker tasks.
type App struct {
	Config           *config.Config
	Log              *logrus.Logger
	MetricsCollector *metrics.MetricsCollector
	TaskQueue        chan scanner.ScanTask
	RateLimiter      *rate.Limiter
	server           *http.Server
}

// NewApp initializes the application by loading configuration, setting up logging, and registering metrics.
func NewApp(configPath string, reg prometheus.Registerer) (*App, error) {
	log := setupLogger()
	cfg, err := loadConfiguration(log, configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	metricsCollector := metrics.NewMetricsCollector()
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	reg.MustRegister(metricsCollector)

	return &App{
		Config:           cfg,
		Log:              log,
		MetricsCollector: metricsCollector,
		TaskQueue:        make(chan scanner.ScanTask, cfg.Performance.TaskQueueSize),
		RateLimiter:      setupRateLimiter(cfg),
	}, nil
}

// Run starts the workers, the scanning loop, the HTTP handlers, and waits for interrupt signals.
func (a *App) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a.Log.Info("Starting workers...")
	a.StartWorkers(ctx)
	go a.enqueueScanTasks(ctx)

	a.SetupHTTPHandlers()
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.StartServer()
	}()

	// Listen for OS signals to initiate a graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt) // can include syscall.SIGTERM, etc.
	select {
	case <-sigCh:
		a.Log.Warn("Received shutdown signal, attempting graceful shutdown...")
		ctxTimeout, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()

		// Cancel background context for workers
		cancel()
		// Shut down the HTTP server gracefully
		if err := a.server.Shutdown(ctxTimeout); err != nil {
			a.Log.WithError(err).Error("HTTP server forced to shutdown")
		} else {
			a.Log.Info("HTTP server shutdown completed gracefully")
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// StartWorkers spins up a set of worker goroutines to handle scanning tasks.
func (a *App) StartWorkers(ctx context.Context) {
	scanner.StartWorkers(ctx, a.Config.Performance.WorkerCount, a.TaskQueue, a.Config, a.MetricsCollector)
}

// SetupHTTPHandlers registers endpoints and attaches them to an HTTP server.
func (a *App) SetupHTTPHandlers() {
	mux := http.NewServeMux()
	mux.HandleFunc("/query", scanner.HandleQuery(a.Config, a.RateLimiter, a.Log, a.TaskQueue, a.MetricsCollector))
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", healthcheck.HealthCheckHandler(a.TaskQueue, a.Config, a.Log))

	// Build the http.Server with timeouts
	a.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", a.Config.Server.Port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// StartServer actually starts the HTTP server listening for requests.
func (a *App) StartServer() error {
	address := a.server.Addr
	a.Log.WithField("address", address).Info("Starting metrics server")
	return a.server.ListenAndServe()
}

// enqueueScanTasks periodically schedules scans for each configured target if enough time has passed.
func (a *App) enqueueScanTasks(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.Log.Info("Stopping enqueueScanTasks due to context cancellation")
			return
		case <-ticker.C:
			for _, target := range a.Config.Targets {
				a.processTarget(ctx, target)
			}
		}
	}
}

// processTarget checks if a scan can run for the given target and enqueues it if so.
func (a *App) processTarget(ctx context.Context, target string) {
	targetKey := createTargetKey(target, a.Config.Scanning.PortRange)

	if !a.MetricsCollector.CanScan(targetKey, a.Config.GetScanIntervalDuration()) {
		a.Log.WithField("target", targetKey).Debug("Ignoring scan, interval not reached")
		return
	}

	if err := a.enqueueScanTask(ctx, target); err != nil {
		a.handleEnqueueError(err, target)
	} else {
		a.MetricsCollector.RegisterScan(targetKey)
		a.logScanEnqueued(target)
	}
}

// createTargetKey forms a unique key for the given target and port range.
func createTargetKey(target, portRange string) string {
	return target + "_" + portRange
}

// enqueueScanTask adds a new scanning task into the queue.
func (a *App) enqueueScanTask(ctx context.Context, target string) error {
	return scanner.EnqueueScanTask(ctx, a.TaskQueue, target, a.Config.Scanning.PortRange, "tcp", a.Config.Scanning.MaxCIDRSize)
}

// handleEnqueueError logs an error if the enqueue process fails.
func (a *App) handleEnqueueError(err error, target string) {
	a.Log.WithFields(logrus.Fields{
		"target": target,
		"error":  err,
	}).Warn("Failed to enqueue scan")
}

// logScanEnqueued logs a successful scan enqueue event.
func (a *App) logScanEnqueued(target string) {
	a.Log.WithField("target", target).Info("Scan enqueued successfully")
}

// setupLogger configures the logging mechanism based on config or defaults.
func setupLogger() *logrus.Logger {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})

	// Example: read from ENV or set a default.
	// If you want advanced config reading, integrate with the config package
	levelStr := os.Getenv("LOG_LEVEL")
	if levelStr == "" {
		levelStr = "info"
	}

	lvl, err := logrus.ParseLevel(levelStr)
	if err != nil {
		lvl = logrus.InfoLevel
	}
	log.SetLevel(lvl)
	return log
}

// loadConfiguration loads the YAML config file and logs essential info.
func loadConfiguration(log *logrus.Logger, configPath string) (*config.Config, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	log.WithField("task_queue_size", cfg.Performance.TaskQueueSize).
		WithField("worker_count", cfg.Performance.WorkerCount).
		Info("Configuration loaded")

	return cfg, nil
}

// setupRateLimiter returns a rate limiter instance using the config values.
func setupRateLimiter(cfg *config.Config) *rate.Limiter {
	// Convert the per-minute rate limit to a per-second float
	return rate.NewLimiter(rate.Limit(cfg.Performance.RateLimit)/60.0, cfg.Performance.RateLimit)
}
