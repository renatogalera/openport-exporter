package collectors

import (
    "log/slog"

    "github.com/prometheus/client_golang/prometheus"
    openmetrics "github.com/renatogalera/openport-exporter/internal/metrics"
)

// Settings carries generic exporter settings (logger, http, etc.). Add as needed.
type Settings struct {
    LogLevel    string
    LogFormat   string
    MetricsPath string
    ListenPort  string
    Address     string
    ConfigPath  string
    EnableGoCollector bool
    EnableBuildInfo   bool
    // Prober (optional /probe endpoint)
    EnableProber       bool
    ProberAllowCIDRs   []string
    ProberRateLimit    float64 // requests per second
    ProberBurst        int
    ProberMaxCIDRSize  int
    ProberMaxConcurrent int
    ProberDefaultTimeout string // e.g., "10s"
    ProberClientAllowCIDRs []string
    ProberMaxPorts      int
    ProberMaxTargets    int
    // Optional auth for /probe
    ProberAuthToken     string
    ProberBasicUser     string
    ProberBasicPass     string
}

// Exporter adapts our internal MetricsCollector to the prometheus.Collector interface.
type Exporter struct {
    mc     *openmetrics.MetricsCollector
    Logger *slog.Logger
}

func NewExporter(mc *openmetrics.MetricsCollector, logger *slog.Logger) *Exporter {
    return &Exporter{mc: mc, Logger: logger}
}

// Describe implements prometheus.Collector by delegating to our MetricsCollector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) { e.mc.Describe(ch) }

// Collect implements prometheus.Collector by delegating to our MetricsCollector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) { e.mc.Collect(ch) }
