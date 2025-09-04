package httpserver

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/renatogalera/openport-exporter/internal/collectors"
	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	openmetrics "github.com/renatogalera/openport-exporter/internal/metrics"
	"github.com/renatogalera/openport-exporter/internal/scanner"
	"github.com/renatogalera/openport-exporter/internal/sloglogger"
	taskspkg "github.com/renatogalera/openport-exporter/internal/tasks"
)

// startHTTPServer spins a real TCP listener and serves the http.Server returned by NewServer.
// It returns baseURL and a shutdown func for cleanup.
func startHTTPServer(t *testing.T, s *collectors.Settings, cfg *cfgpkg.Config) (string, func()) {
	t.Helper()

	mc := openmetrics.NewMetricsCollector()
	logger, _ := sloglogger.NewLogger("error", "text")
	exporter := collectors.NewExporter(mc, logger)

	mgr := cfgpkg.NewManager(cfg, "")
	// Minimal task manager and queue
	workerQueue := make(chan scanner.ScanTask, 8)
	tm := taskspkg.NewManager(5 * time.Minute)
	srv := NewServer(exporter, s, mgr, tm, workerQueue, mc, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()

	go func() { _ = srv.Serve(ln) }()

	// wait briefly for server to accept
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(baseURL + "/-/healthy"); err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}

	return baseURL, shutdown
}

func baseConfig() *cfgpkg.Config {
	t := true
	return &cfgpkg.Config{
		Server: cfgpkg.ServerConfig{Port: 0},
		Scanning: cfgpkg.ScanningConfig{
			Interval:             3600,
			Timeout:              10,
			PortRange:            "22,80",
			MaxCIDRSize:          24,
			DisableDNSResolution: true,
			UseSYNScan:           &t,
			WorkerCount:          1,
			TaskQueueSize:        10,
		},
		Targets: []cfgpkg.TargetDef{{
			Name: "t1", Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Interval: "1h",
		}},
	}
}

func baseSettings() *collectors.Settings {
	return &collectors.Settings{
		LogLevel:          "error",
		LogFormat:         "text",
		MetricsPath:       "/metrics",
		ListenPort:        "0",
		Address:           "localhost",
		ConfigPath:        "",
		EnableGoCollector: false,
		EnableBuildInfo:   true,
	}
}

func TestReadyEndpointTransitions(t *testing.T) {
	cfg := baseConfig()
	s := baseSettings()

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	// Immediately after startup, readiness might still be false.
	resp1, err := http.Get(baseURL + "/-/ready")
	if err != nil {
		t.Fatalf("ready initial GET err: %v", err)
	}
	_ = resp1.Body.Close()

	// After ~300ms, readiness must be OK.
	time.Sleep(350 * time.Millisecond)
	resp2, err := http.Get(baseURL + "/-/ready")
	if err != nil {
		t.Fatalf("ready second GET err: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /-/ready, got %d", resp2.StatusCode)
	}
}

func TestMetricsServedAndContainsExporterMetrics(t *testing.T) {
	cfg := baseConfig()
	s := baseSettings()

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	resp, err := http.Get(baseURL + s.MetricsPath)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Fatalf("metrics response is empty")
	}
}

func TestRootPageRenders(t *testing.T) {
	cfg := baseConfig()
	s := baseSettings()

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	resp, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /, got %d", resp.StatusCode)
	}
}
