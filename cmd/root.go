package cmd

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/common/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/renatogalera/openport-exporter/internal/collectors"
	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	"github.com/renatogalera/openport-exporter/internal/httpserver"
	openmetrics "github.com/renatogalera/openport-exporter/internal/metrics"
	prioq "github.com/renatogalera/openport-exporter/internal/priority"
	"github.com/renatogalera/openport-exporter/internal/scanner"
	"github.com/renatogalera/openport-exporter/internal/sloglogger"
	taskspkg "github.com/renatogalera/openport-exporter/internal/tasks"
)

const (
	defaultLogLevel          = "info"
	defaultLogFormat         = "json"
	defaultMetricsPath       = "/metrics"
	defaultListenPort        = "9919"
	defaultAddress           = "localhost"
	defaultConfigPath        = "config.yaml"
	defaultEnableGoCollector = false
	defaultEnableBuildInfo   = true
)

var settings collectors.Settings

var rootCmd = &cobra.Command{
	Use:   "openport-exporter",
	Short: "Prometheus exporter for open ports using Nmap",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return validateSettings()
	},
	RunE: func(cmd *cobra.Command, args []string) error { return run() },
}

func init() {
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	// ENV defaults
	viper.AutomaticEnv()
	viper.SetDefault("LOG_LEVEL", defaultLogLevel)
	viper.SetDefault("LOG_FORMAT", defaultLogFormat)
	viper.SetDefault("METRICS_PATH", defaultMetricsPath)
	viper.SetDefault("LISTEN_PORT", defaultListenPort)
	viper.SetDefault("ADDRESS", defaultAddress)
	viper.SetDefault("CONFIG_PATH", defaultConfigPath)
	viper.SetDefault("ENABLE_GO_COLLECTOR", defaultEnableGoCollector)
	viper.SetDefault("ENABLE_BUILD_INFO", defaultEnableBuildInfo)

	// Flags
	rootCmd.Flags().StringVar(&settings.LogLevel, "log.level", defaultLogLevel, "Log level (debug|info|warn|error)")
	_ = viper.BindPFlag("LOG_LEVEL", rootCmd.Flags().Lookup("log.level"))

	rootCmd.Flags().StringVar(&settings.LogFormat, "log.format", defaultLogFormat, "Log format (text|json)")
	_ = viper.BindPFlag("LOG_FORMAT", rootCmd.Flags().Lookup("log.format"))

	rootCmd.Flags().StringVar(&settings.MetricsPath, "metrics.path", defaultMetricsPath, "Path to expose metrics")
	_ = viper.BindPFlag("METRICS_PATH", rootCmd.Flags().Lookup("metrics.path"))

	rootCmd.Flags().StringVar(&settings.ListenPort, "listen.port", defaultListenPort, "Port to listen on")
	_ = viper.BindPFlag("LISTEN_PORT", rootCmd.Flags().Lookup("listen.port"))

	rootCmd.Flags().StringVar(
		&settings.Address,
		"address",
		defaultAddress,
		"Exporter address for informational pages",
	)
	_ = viper.BindPFlag("ADDRESS", rootCmd.Flags().Lookup("address"))

	rootCmd.Flags().StringVar(&settings.ConfigPath, "config.path", defaultConfigPath, "Path to YAML config file")
	_ = viper.BindPFlag("CONFIG_PATH", rootCmd.Flags().Lookup("config.path"))

	rootCmd.Flags().BoolVar(
		&settings.EnableGoCollector,
		"collector.go",
		defaultEnableGoCollector,
		"Enable Go runtime metrics collector",
	)
	_ = viper.BindPFlag("ENABLE_GO_COLLECTOR", rootCmd.Flags().Lookup("collector.go"))

	rootCmd.Flags().BoolVar(
		&settings.EnableBuildInfo,
		"collector.build_info",
		defaultEnableBuildInfo,
		"Enable build_info collector",
	)
	_ = viper.BindPFlag("ENABLE_BUILD_INFO", rootCmd.Flags().Lookup("collector.build_info"))

	// Snapshot the effective values from viper
	settings.LogLevel = viper.GetString("LOG_LEVEL")
	settings.LogFormat = viper.GetString("LOG_FORMAT")
	settings.MetricsPath = viper.GetString("METRICS_PATH")
	settings.ListenPort = viper.GetString("LISTEN_PORT")
	settings.Address = viper.GetString("ADDRESS")
	settings.ConfigPath = viper.GetString("CONFIG_PATH")
	settings.EnableGoCollector = viper.GetBool("ENABLE_GO_COLLECTOR")
	settings.EnableBuildInfo = viper.GetBool("ENABLE_BUILD_INFO")
}

func validateSettings() error {
	if settings.LogLevel == "" {
		return fmt.Errorf("missing LOG_LEVEL")
	}
	return nil
}

func run() error {
	// Logger
	logger, _ := sloglogger.NewLogger(settings.LogLevel, settings.LogFormat)
	logger.Info("starting openport-exporter", "version", version.Info())

	// Config
	cfg, err := cfgpkg.LoadConfig(settings.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	mgr := cfgpkg.NewManager(cfg, settings.ConfigPath)
	mc := openmetrics.NewMetricsCollector()
	exporter := collectors.NewExporter(mc, logger)

	// Background pipeline
	queueSize := cfg.Scheduler.TaskQueueSize
	if queueSize <= 0 {
		queueSize = cfg.Scanning.TaskQueueSize
	}
	workerQueue := make(chan scanner.ScanTask, queueSize)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup sweeper with TTL calculation
	mc.StartSweeper(ctx, mgr.GetTTL())

	// Configure callback for configuration reloads
	mgr.SetOnReload(func(old, newCfg *cfgpkg.Config) {
		oldTTL := cfgpkg.TTLForConfig(old)
		newTTL := cfgpkg.TTLForConfig(newCfg)

		if newTTL != oldTTL {
			mc.SetSweeperTTL(newTTL)
			logger.Info("sweeper TTL updated", "old_ttl", oldTTL.String(), "new_ttl", newTTL.String())
		}

		logger.Info("configuration reloaded",
			"targets", len(newCfg.Targets),
			"interval", newCfg.GetScanIntervalDuration().String(),
			"ttl", newTTL.String())
	})

	// TaskManager with dedupe TTL
	dedupeTTL := time.Duration(15) * time.Minute
	if d, err := time.ParseDuration(cfg.Scheduler.DedupeTTL); err == nil && d > 0 {
		dedupeTTL = d
	}
	taskManager := taskspkg.NewManager(dedupeTTL)

	// Priority dispatcher
	prio := prioq.NewQueue(workerQueue)
	prio.Start()

	// Periodic GC of finished tasks (defaults: keep max 10000 for up to 24h)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				maxTasks := cfg.Scheduler.TaskGCMax
				maxAge := 24 * time.Hour
				if d, err := time.ParseDuration(cfg.Scheduler.TaskGCMaxAge); err == nil && d > 0 {
					maxAge = d
				}
				taskManager.GC(maxTasks, maxAge)
			}
		}
	}()

	// Workers read a snapshot per task
	workerCount := cfg.Scheduler.WorkerCount
	if workerCount <= 0 {
		workerCount = cfg.Scanning.WorkerCount
	}
	scanner.StartWorkers(
		ctx,
		workerCount,
		workerQueue,
		mgr,
		mc,
		logger,
		taskManager,
		func(t scanner.ScanTask, p string) bool {
			// re-enqueue via priority queue if available
			if prio != nil {
				return prio.Enqueue(p, t)
			}
			select {
			case workerQueue <- t:
				return true
			default:
			}
			return false
		},
	)

	// Scheduler: per-target interval using MetricsCollector.CanScan guard
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c := mgr.Get()
				for _, td := range c.Targets {
					// Determine effective interval
					d, err := time.ParseDuration(td.Interval)
					if err != nil || d <= 0 {
						d = c.GetScanIntervalDuration()
					}
					// Compose key for CanScan
					key := scanner.CreateTargetKeyFor(td.Target, td.PortRange, td.Protocol)
					if mc.CanScan(key, d) {
						j := time.Duration(rand.IntN(250)) * time.Millisecond
						select {
						case <-ctx.Done():
							return
						case <-time.After(j):
						}
						if err := scanner.EnqueueScanTask(ctx, workerQueue, td.Target, td.PortRange, td.Protocol, c.Scanning.MaxCIDRSize); err != nil {
							mc.IncSchedulerEnqueueFailed()
							continue
						}
						mc.RegisterScan(key)
						mc.SetPerTargetTTL(
							scanner.CreateTargetKeyFor(
								td.Target,
								td.PortRange,
								td.Protocol,
							),
							3*d,
						)
					}
				}
			}
		}
	}()

	srv := httpserver.NewServer(exporter, &settings, mgr, taskManager, workerQueue, mc, prio)

	// Signals: graceful stop + SIGHUP reload
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				logger.Info("SIGHUP received, reloading configuration")
				if err := mgr.Reload(); err != nil {
					logger.Error("SIGHUP reload failed", "error", err)
					continue
				}
				// The reload callback will handle TTL updates and logging
			default:
				logger.Info("shutdown signal received", "signal", sig.String())
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer shutdownCancel()
				_ = srv.Shutdown(shutdownCtx)
				cancel()
				return
			}
		}
	}()

	logger.Info("listening", "addr", srv.Addr, "metrics", settings.MetricsPath)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server: %w", err)
	}
	if prio != nil {
		prio.Stop()
		prio.Wait()
	}
	close(workerQueue)
	logger.Info("server gracefully stopped")
	return nil
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		return fmt.Errorf("cmd execute: %w", err)
	}
	return nil
}
