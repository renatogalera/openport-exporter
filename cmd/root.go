package cmd

import (
	"context"
	"fmt"
	"math/rand"
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
	"github.com/renatogalera/openport-exporter/internal/scanner"
	"github.com/renatogalera/openport-exporter/internal/sloglogger"
)

const (
	defaultLogLevel             = "info"
	defaultLogFormat            = "json"
	defaultMetricsPath          = "/metrics"
	defaultListenPort           = "9919"
	defaultAddress              = "localhost"
	defaultConfigPath           = "config.yaml"
	defaultEnableGoCollector    = false
	defaultEnableBuildInfo      = true
	defaultEnableProber         = false
	defaultProberRateLimit      = 1.0
	defaultProberBurst          = 1
	defaultProberMaxCIDRSize    = 24
	defaultProberMaxConcurrent  = 1
	defaultProberDefaultTimeout = "10s"
)

var (
	settings collectors.Settings
)

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
	viper.SetDefault("ENABLE_PROBER", defaultEnableProber)
	viper.SetDefault("PROBER_RATE_LIMIT", defaultProberRateLimit)
	viper.SetDefault("PROBER_BURST", defaultProberBurst)
	viper.SetDefault("PROBER_MAX_CIDR_SIZE", defaultProberMaxCIDRSize)
	viper.SetDefault("PROBER_MAX_CONCURRENT", defaultProberMaxConcurrent)
	viper.SetDefault("PROBER_DEFAULT_TIMEOUT", defaultProberDefaultTimeout)
	viper.SetDefault("PROBER_CLIENT_ALLOW_CIDRS", []string{})
	viper.SetDefault("PROBER_MAX_PORTS", 4096)
	viper.SetDefault("PROBER_MAX_TARGETS", 32)
	viper.SetDefault("PROBER_AUTH_TOKEN", "")
	viper.SetDefault("PROBER_BASIC_USER", "")
	viper.SetDefault("PROBER_BASIC_PASS", "")
	viper.SetDefault("PROBER_ALLOW_CIDRS", []string{})

	// Flags
	rootCmd.Flags().StringVar(&settings.LogLevel, "log.level", defaultLogLevel, "Log level (debug|info|warn|error)")
	_ = viper.BindPFlag("LOG_LEVEL", rootCmd.Flags().Lookup("log.level"))

	rootCmd.Flags().StringVar(&settings.LogFormat, "log.format", defaultLogFormat, "Log format (text|json)")
	_ = viper.BindPFlag("LOG_FORMAT", rootCmd.Flags().Lookup("log.format"))

	rootCmd.Flags().StringVar(&settings.MetricsPath, "metrics.path", defaultMetricsPath, "Path to expose metrics")
	_ = viper.BindPFlag("METRICS_PATH", rootCmd.Flags().Lookup("metrics.path"))

	rootCmd.Flags().StringVar(&settings.ListenPort, "listen.port", defaultListenPort, "Port to listen on")
	_ = viper.BindPFlag("LISTEN_PORT", rootCmd.Flags().Lookup("listen.port"))

	rootCmd.Flags().StringVar(&settings.Address, "address", defaultAddress, "Exporter address for informational pages")
	_ = viper.BindPFlag("ADDRESS", rootCmd.Flags().Lookup("address"))

	rootCmd.Flags().StringVar(&settings.ConfigPath, "config.path", defaultConfigPath, "Path to YAML config file")
	_ = viper.BindPFlag("CONFIG_PATH", rootCmd.Flags().Lookup("config.path"))

	rootCmd.Flags().BoolVar(&settings.EnableGoCollector, "collector.go", defaultEnableGoCollector, "Enable Go runtime metrics collector")
	_ = viper.BindPFlag("ENABLE_GO_COLLECTOR", rootCmd.Flags().Lookup("collector.go"))

	rootCmd.Flags().BoolVar(&settings.EnableBuildInfo, "collector.build_info", defaultEnableBuildInfo, "Enable build_info collector")
	_ = viper.BindPFlag("ENABLE_BUILD_INFO", rootCmd.Flags().Lookup("collector.build_info"))

	rootCmd.Flags().BoolVar(&settings.EnableProber, "prober.enable", defaultEnableProber, "Enable /probe endpoint (disabled by default)")
	_ = viper.BindPFlag("ENABLE_PROBER", rootCmd.Flags().Lookup("prober.enable"))

	rootCmd.Flags().StringSliceVar(&settings.ProberAllowCIDRs, "prober.allow_cidr", []string{}, "CIDRs allowed for /probe (repeatable)")
	_ = viper.BindPFlag("PROBER_ALLOW_CIDRS", rootCmd.Flags().Lookup("prober.allow_cidr"))

	rootCmd.Flags().Float64Var(&settings.ProberRateLimit, "prober.rate_limit", defaultProberRateLimit, "/probe rate limit (requests per second)")
	_ = viper.BindPFlag("PROBER_RATE_LIMIT", rootCmd.Flags().Lookup("prober.rate_limit"))

	rootCmd.Flags().IntVar(&settings.ProberBurst, "prober.burst", defaultProberBurst, "/probe rate limiter burst")
	_ = viper.BindPFlag("PROBER_BURST", rootCmd.Flags().Lookup("prober.burst"))

	rootCmd.Flags().IntVar(&settings.ProberMaxCIDRSize, "prober.max_cidr_size", defaultProberMaxCIDRSize, "Maximum CIDR size allowed for /probe split")
	_ = viper.BindPFlag("PROBER_MAX_CIDR_SIZE", rootCmd.Flags().Lookup("prober.max_cidr_size"))

	rootCmd.Flags().IntVar(&settings.ProberMaxConcurrent, "prober.max_concurrent", defaultProberMaxConcurrent, "Maximum concurrent /probe requests")
	_ = viper.BindPFlag("PROBER_MAX_CONCURRENT", rootCmd.Flags().Lookup("prober.max_concurrent"))

	rootCmd.Flags().StringVar(&settings.ProberDefaultTimeout, "prober.default_timeout", defaultProberDefaultTimeout, "Default /probe timeout, e.g. 10s")
	_ = viper.BindPFlag("PROBER_DEFAULT_TIMEOUT", rootCmd.Flags().Lookup("prober.default_timeout"))

	rootCmd.Flags().StringSliceVar(&settings.ProberClientAllowCIDRs, "prober.client_allow_cidr", []string{}, "CIDRs allowed to call /probe (client IPs)")
	_ = viper.BindPFlag("PROBER_CLIENT_ALLOW_CIDRS", rootCmd.Flags().Lookup("prober.client_allow_cidr"))

	rootCmd.Flags().IntVar(&settings.ProberMaxPorts, "prober.max_ports", 4096, "Maximum number of ports allowed in /probe selection")
	_ = viper.BindPFlag("PROBER_MAX_PORTS", rootCmd.Flags().Lookup("prober.max_ports"))

	rootCmd.Flags().IntVar(&settings.ProberMaxTargets, "prober.max_targets", 32, "Maximum number of targets per /probe request")
	_ = viper.BindPFlag("PROBER_MAX_TARGETS", rootCmd.Flags().Lookup("prober.max_targets"))

	rootCmd.Flags().StringVar(&settings.ProberAuthToken, "prober.auth_token", "", "Bearer token required for /probe (optional)")
	_ = viper.BindPFlag("PROBER_AUTH_TOKEN", rootCmd.Flags().Lookup("prober.auth_token"))

	rootCmd.Flags().StringVar(&settings.ProberBasicUser, "prober.basic_user", "", "Basic auth username for /probe (optional)")
	_ = viper.BindPFlag("PROBER_BASIC_USER", rootCmd.Flags().Lookup("prober.basic_user"))

	rootCmd.Flags().StringVar(&settings.ProberBasicPass, "prober.basic_pass", "", "Basic auth password for /probe (optional)")
	_ = viper.BindPFlag("PROBER_BASIC_PASS", rootCmd.Flags().Lookup("prober.basic_pass"))

	// Snapshot the effective values from viper
	settings.LogLevel = viper.GetString("LOG_LEVEL")
	settings.LogFormat = viper.GetString("LOG_FORMAT")
	settings.MetricsPath = viper.GetString("METRICS_PATH")
	settings.ListenPort = viper.GetString("LISTEN_PORT")
	settings.Address = viper.GetString("ADDRESS")
	settings.ConfigPath = viper.GetString("CONFIG_PATH")
	settings.EnableGoCollector = viper.GetBool("ENABLE_GO_COLLECTOR")
	settings.EnableBuildInfo = viper.GetBool("ENABLE_BUILD_INFO")
	settings.EnableProber = viper.GetBool("ENABLE_PROBER")
	settings.ProberAllowCIDRs = viper.GetStringSlice("PROBER_ALLOW_CIDRS")
	settings.ProberRateLimit = viper.GetFloat64("PROBER_RATE_LIMIT")
	settings.ProberBurst = viper.GetInt("PROBER_BURST")
	settings.ProberMaxCIDRSize = viper.GetInt("PROBER_MAX_CIDR_SIZE")
	settings.ProberMaxConcurrent = viper.GetInt("PROBER_MAX_CONCURRENT")
	settings.ProberDefaultTimeout = viper.GetString("PROBER_DEFAULT_TIMEOUT")
	settings.ProberClientAllowCIDRs = viper.GetStringSlice("PROBER_CLIENT_ALLOW_CIDRS")
	settings.ProberMaxPorts = viper.GetInt("PROBER_MAX_PORTS")
	settings.ProberMaxTargets = viper.GetInt("PROBER_MAX_TARGETS")
	settings.ProberAuthToken = viper.GetString("PROBER_AUTH_TOKEN")
	settings.ProberBasicUser = viper.GetString("PROBER_BASIC_USER")
	settings.ProberBasicPass = viper.GetString("PROBER_BASIC_PASS")
}

func validateSettings() error {
	if settings.LogLevel == "" {
		return fmt.Errorf("missing LOG_LEVEL")
	}
	// Secure-by-default: if /probe is enabled, require at least one allow-list.
	if settings.EnableProber &&
		len(settings.ProberAllowCIDRs) == 0 &&
		len(settings.ProberClientAllowCIDRs) == 0 {
		return fmt.Errorf("ENABLE_PROBER requires at least one of PROBER_ALLOW_CIDRS or PROBER_CLIENT_ALLOW_CIDRS to be set for safety")
	}
	return nil
}

func run() error {
	rand.Seed(time.Now().UnixNano())

	// Logger
	logger, _ := sloglogger.NewLogger(settings.LogLevel, settings.LogFormat)
	logger.Info("starting openport-exporter", "version", version.Info())

	// Config
	cfg, err := cfgpkg.LoadConfig(settings.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Metrics and exporter
	mc := openmetrics.NewMetricsCollector()
	exporter := collectors.NewExporter(mc, logger)

	// Merge /prober settings from config if present (config wins)
	if cfg.Prober != nil {
		settings.EnableProber = cfg.Prober.Enabled
		if len(cfg.Prober.AllowCIDRs) > 0 {
			settings.ProberAllowCIDRs = cfg.Prober.AllowCIDRs
		}
		if len(cfg.Prober.ClientAllowCIDRs) > 0 {
			settings.ProberClientAllowCIDRs = cfg.Prober.ClientAllowCIDRs
		}
		if cfg.Prober.RateLimit > 0 {
			settings.ProberRateLimit = cfg.Prober.RateLimit
		}
		if cfg.Prober.Burst > 0 {
			settings.ProberBurst = cfg.Prober.Burst
		}
		if cfg.Prober.MaxCIDRSize > 0 {
			settings.ProberMaxCIDRSize = cfg.Prober.MaxCIDRSize
		}
		if cfg.Prober.MaxConcurrent > 0 {
			settings.ProberMaxConcurrent = cfg.Prober.MaxConcurrent
		}
		if cfg.Prober.DefaultTimeout != "" {
			settings.ProberDefaultTimeout = cfg.Prober.DefaultTimeout
		}
		if cfg.Prober.MaxPorts > 0 {
			settings.ProberMaxPorts = cfg.Prober.MaxPorts
		}
		if cfg.Prober.MaxTargets > 0 {
			settings.ProberMaxTargets = cfg.Prober.MaxTargets
		}
		if cfg.Prober.AuthToken != "" {
			settings.ProberAuthToken = cfg.Prober.AuthToken
		}
		if cfg.Prober.BasicUser != "" {
			settings.ProberBasicUser = cfg.Prober.BasicUser
		}
		if cfg.Prober.BasicPass != "" {
			settings.ProberBasicPass = cfg.Prober.BasicPass
		}
	}

	// Background pipeline
	taskQueue := make(chan scanner.ScanTask, cfg.Scanning.TaskQueueSize)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// GC stale series past 3x scan interval.
	mc.StartSweeper(ctx, 3*cfg.GetScanIntervalDuration())

	// Workers
	scanner.StartWorkers(ctx, cfg.Scanning.WorkerCount, taskQueue, cfg, mc, logger)

	// Periodic enqueue with slight jitter per target (keeps /metrics fast).
	go func() {
		ticker := time.NewTicker(cfg.GetScanIntervalDuration())
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, target := range cfg.Targets {
					j := time.Duration(rand.Intn(250)) * time.Millisecond
					select {
					case <-ctx.Done():
						return
					case <-time.After(j):
					}
					_ = scanner.EnqueueScanTask(ctx, taskQueue, target, cfg.Scanning.PortRange, "tcp", cfg.Scanning.MaxCIDRSize)
				}
			}
		}
	}()

	// HTTP server
	srv := httpserver.NewServer(exporter, &settings, cfg)

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutdown signal received")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
		cancel()
	}()

	logger.Info("listening", "addr", srv.Addr, "metrics", settings.MetricsPath)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}

	close(taskQueue)
	logger.Info("server gracefully stopped")
	return nil
}

func Execute() error { return rootCmd.Execute() }
