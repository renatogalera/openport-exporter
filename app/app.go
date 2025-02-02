package app

import (
	"context"
	"fmt"
	"net/http"
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

type App struct {
	Config           *config.Config
	Log              *logrus.Logger
	MetricsCollector *metrics.MetricsCollector
	TaskQueue        chan scanner.ScanTask
	RateLimiter      *rate.Limiter
}

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

func (a *App) Run() error {
	ctx := context.Background()

	a.StartWorkers(ctx)
	go a.enqueueScanTasks(ctx)

	a.SetupHTTPHandlers()
	return a.StartServer()
}

func setupLogger() *logrus.Logger {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	return log
}

func loadConfiguration(log *logrus.Logger, configPath string) (*config.Config, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	log.WithField("task_queue_size", cfg.Performance.TaskQueueSize).Info("Task queue size")
	return cfg, nil
}

func setupRateLimiter(cfg *config.Config) *rate.Limiter {
	return rate.NewLimiter(rate.Limit(cfg.Performance.RateLimit)/60.0, cfg.Performance.RateLimit)
}

func (a *App) StartWorkers(ctx context.Context) {
	a.Log.Info("Starting workers")
	scanner.StartWorkers(ctx, a.Config.Performance.WorkerCount, a.TaskQueue, a.Config, a.MetricsCollector)
}

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

func (a *App) SetupHTTPHandlers() {
	http.HandleFunc("/query", scanner.HandleQuery(a.Config, a.RateLimiter, a.Log, a.TaskQueue, a.MetricsCollector))
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", healthcheck.HealthCheckHandler(a.TaskQueue, a.Config, a.Log))
}

func (a *App) StartServer() error {
	address := fmt.Sprintf(":%d", a.Config.Server.Port)
	a.Log.WithField("address", address).Info("Metrics server started")

	return http.ListenAndServe(address, nil)
}
