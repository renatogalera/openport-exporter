package collectors

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	openmetrics "github.com/renatogalera/openport-exporter/internal/metrics"
)

// Settings carries generic exporter settings (logger, http, etc.). Add as needed.
type Settings struct {
	LogLevel          string
	LogFormat         string
	MetricsPath       string
	ListenPort        string
	Address           string
	ConfigPath        string
	EnableGoCollector bool
	EnableBuildInfo   bool
}

// Exporter adapts our internal Collector to the prometheus.Collector interface.
type Exporter struct {
	mc     *openmetrics.Collector
	Logger *slog.Logger
}

func NewExporter(mc *openmetrics.Collector, logger *slog.Logger) *Exporter {
	return &Exporter{mc: mc, Logger: logger}
}

// Describe implements prometheus.Collector by delegating to our Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) { e.mc.Describe(ch) }

// Collect implements prometheus.Collector by delegating to our Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) { e.mc.Collect(ch) }
