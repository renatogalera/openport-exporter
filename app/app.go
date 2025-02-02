package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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

// App holds the main application context.
type App struct {
	Config           *config.Config
	Log              *logrus.Logger
	MetricsCollector *metrics.MetricsCollector
	TaskQueue        chan scanner.ScanTask
	RateLimiter      *rate.Limiter

	// We store the listener so that tests can retrieve the actual chosen port
	serverListener net.Listener

	Mux *http.ServeMux
}

// NewApp initializes and returns a new App instance.
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
		// Create a fresh mux
		Mux: http.NewServeMux(),
	}, nil
}

// Run starts the workers, enqueues tasks, sets up HTTP handlers, and starts the server with graceful shutdown.
func (a *App) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Listen for OS signals for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Start workers (injecting our logger) and enqueue tasks.
	go scanner.StartWorkers(ctx, a.Config.Performance.WorkerCount, a.TaskQueue, a.Config, a.MetricsCollector, a.Log)
	go a.enqueueScanTasks(ctx)

	a.SetupHTTPHandlers()

	// Create an HTTP server.
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", a.Config.Server.Port),
		Handler: a.Mux,
	}

	// Start the server in a separate goroutine.
	serverErrCh := make(chan error, 1)
	go func() {
		a.Log.WithField("address", srv.Addr).Info("Metrics server starting")
		serverErrCh <- srv.ListenAndServe()
	}()

	// Wait for a shutdown signal or a server error.
	select {
	case sig := <-sigCh:
		a.Log.WithField("signal", sig).Info("Shutdown signal received")
	case err := <-serverErrCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	}

	// Initiate graceful shutdown.
	cancel()
	ctxShutdown, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(ctxShutdown); err != nil {
		a.Log.Error("Server Shutdown:", err)
	}

	// Close the task queue so that workers can exit.
	close(a.TaskQueue)

	a.Log.Info("Server gracefully stopped")
	return nil
}

// setupLogger configures and returns a new logrus logger.
func setupLogger() *logrus.Logger {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	return log
}

// loadConfiguration loads the YAML config and logs some fields.
func loadConfiguration(log *logrus.Logger, configPath string) (*config.Config, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	log.WithField("task_queue_size", cfg.Performance.TaskQueueSize).Info("Task queue size")
	return cfg, nil
}

// setupRateLimiter creates a rate limiter based on config.
func setupRateLimiter(cfg *config.Config) *rate.Limiter {
	// If RateLimit = N, the user wants N requests per minute -> N/60 per second.
	return rate.NewLimiter(rate.Limit(cfg.Performance.RateLimit)/60.0, cfg.Performance.RateLimit)
}

// enqueueScanTasks periodically queues scan tasks for each configured target.
func (a *App) enqueueScanTasks(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, target := range a.Config.Targets {
				a.processTarget(ctx, target)
			}
		}
	}
}

// processTarget decides if a target should be enqueued for scanning.
func (a *App) processTarget(ctx context.Context, target string) {
	targetKey := createTargetKey(target, a.Config.Scanning.PortRange)
	if !a.MetricsCollector.CanScan(targetKey, a.Config.GetScanIntervalDuration()) {
		a.Log.WithField("target", targetKey).Info("Ignoring scan due to interval not reached")
		return
	}
	if err := a.enqueueScanTask(ctx, target); err != nil {
		a.handleEnqueueError(err, target)
	} else {
		a.MetricsCollector.RegisterScan(targetKey)
		a.logScanEnqueued(target)
	}
}

func createTargetKey(target, portRange string) string {
	return target + "_" + portRange
}

func (a *App) enqueueScanTask(ctx context.Context, target string) error {
	return scanner.EnqueueScanTask(ctx, a.TaskQueue, target, a.Config.Scanning.PortRange, "tcp", a.Config.Scanning.MaxCIDRSize)
}

func (a *App) handleEnqueueError(err error, target string) {
	a.Log.WithFields(logrus.Fields{
		"target": target,
		"error":  err,
	}).Warn("Failed to enqueue scan")
}

func (a *App) logScanEnqueued(target string) {
	a.Log.WithField("target", target).Info("Scan enqueued successfully")
}

// SetupHTTPHandlers registers our HTTP endpoints on the mux.
func (a *App) SetupHTTPHandlers() {
	a.Mux.HandleFunc("/query", scanner.HandleQuery(a.Config, a.RateLimiter, a.Log, a.TaskQueue, a.MetricsCollector))
	a.Mux.Handle("/metrics", promhttp.Handler())
	a.Mux.HandleFunc("/healthz", healthcheck.HealthCheckHandler(a.TaskQueue, a.Config, a.Log))
}

// StartServer listens on the configured port (or ephemeral if port == 0) and serves.
func (a *App) StartServer() error {
	address := fmt.Sprintf(":%d", a.Config.Server.Port)
	a.Log.WithField("address", address).Info("Metrics server starting")

	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	a.serverListener = ln

	a.Log.WithField("address", ln.Addr().String()).Info("Metrics server started")
	return http.Serve(ln, a.Mux)
}

// --------------------------------------------------------------------------
// Additional wrapper methods added to support tests
// --------------------------------------------------------------------------

// StartWorkers is a wrapper that starts scan workers.
func (a *App) StartWorkers(ctx context.Context) {
	scanner.StartWorkers(ctx, a.Config.Performance.WorkerCount, a.TaskQueue, a.Config, a.MetricsCollector, a.Log)
}

// Start is a wrapper method to start the HTTP server.
func (a *App) Start() error {
	return a.StartServer()
}
