package httpserver

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/renatogalera/openport-exporter/internal/collectors"
	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	openmetrics "github.com/renatogalera/openport-exporter/internal/metrics"
	"github.com/renatogalera/openport-exporter/internal/sloglogger"
)

// startHTTPServer spins a real TCP listener and serves the http.Server returned by NewServer.
// It returns baseURL and a shutdown func for cleanup.
func startHTTPServer(t *testing.T, s *collectors.Settings, cfg *cfgpkg.Config) (string, func()) {
	t.Helper()

	// Minimal exporter and logger for the test registry.
	mc := openmetrics.NewMetricsCollector()
	logger, _ := sloglogger.NewLogger("error", "text")
	exporter := collectors.NewExporter(mc, logger)

	// Build server/mux.
	srv := NewServer(exporter, s, cfg)

	// Bind to a free localhost port and serve.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()

	// Serve in background.
	go func() {
		_ = srv.Serve(ln) // will exit when Shutdown is called
	}()

	// Simple health-waiter (server might need a few ms to accept).
	deadline := time.Now().Add(1 * time.Second)
	for {
		if time.Now().After(deadline) {
			break
		}
		if resp, err := http.Get(baseURL + "/-/healthy"); err == nil && resp.StatusCode > 0 {
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
	// Minimal config; no targets required to test handlers.
	// Keep timeouts low so derived durations are bounded.
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
		Targets: []string{},
		Prober:  &cfgpkg.ProberConfig{Enabled: true},
	}
}

func baseSettingsWithProber() *collectors.Settings {
	return &collectors.Settings{
		LogLevel:                "error",
		LogFormat:               "text",
		MetricsPath:             "/metrics",
		ListenPort:              "0", // ignored because we use srv.Serve(ln)
		Address:                 "localhost",
		ConfigPath:              "",
		EnableGoCollector:       false,
		EnableBuildInfo:         true,
		EnableProber:            true,
		ProberAllowCIDRs:        []string{"127.0.0.0/8"}, // allow localhost targets by default
		ProberClientAllowCIDRs:  []string{"127.0.0.0/8"}, // only localhost may call /probe
		ProberRateLimit:         1000,                    // effectively no limit for most tests
		ProberBurst:             1000,
		ProberMaxCIDRSize:       24,
		ProberMaxConcurrent:     8,
		ProberDefaultTimeout:    "1s",
		ProberMaxPorts:          1024,
		ProberMaxTargets:        32,
		ProberAuthToken:         "",
		ProberBasicUser:         "",
		ProberBasicPass:         "",
	}
}

// --- Tests ---

func TestReadyEndpointTransitions(t *testing.T) {
	cfg := baseConfig()
	s := baseSettingsWithProber()

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	// Immediately after startup, readiness should be 503 (before async flip).
	resp1, err := http.Get(baseURL + "/-/ready")
	if err != nil {
		t.Fatalf("ready initial GET err: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusServiceUnavailable && resp1.StatusCode != http.StatusOK {
		// Allow some environments to be fast; accept either 503 or 200 here.
		t.Fatalf("unexpected initial ready status: %d", resp1.StatusCode)
	}

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
	s := baseSettingsWithProber()

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
	text := string(body)
	// Expect one of our exporter metrics (from MetricsCollector).
	if !strings.Contains(text, "openport_task_queue_size") {
		t.Fatalf("metrics output missing expected metric: %s", "openport_task_queue_size")
	}
}

func TestProbeMethodNotAllowed(t *testing.T) {
	cfg := baseConfig()
	s := baseSettingsWithProber()

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/probe", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /probe: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST /probe, got %d", resp.StatusCode)
	}
}

func TestProbeAuth_EitherBearerOrBasicAccepted(t *testing.T) {
	cfg := baseConfig()
	s := baseSettingsWithProber()
	// Configure both auth methods.
	s.ProberAuthToken = "secret-token"
	s.ProberBasicUser = "u"
	s.ProberBasicPass = "p"

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	// Case 1: Bearer auth accepted; request will later fail due to missing ports (400),
	// which proves auth gate passed.
	{
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/probe?target=127.0.0.1", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /probe with bearer: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 (missing ports) after bearer auth ok, got %d", resp.StatusCode)
		}
	}

	// Case 2: Basic auth accepted; again expect 400 due to missing ports.
	{
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/probe?target=127.0.0.1", nil)
		req.SetBasicAuth("u", "p")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /probe with basic: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 (missing ports) after basic auth ok, got %d", resp.StatusCode)
		}
	}

	// Case 3: No auth → 401.
	{
		resp, err := http.Get(baseURL + "/probe?target=127.0.0.1")
		if err != nil {
			t.Fatalf("GET /probe without auth: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 when no auth provided, got %d", resp.StatusCode)
		}
	}
}

func TestProbeClientAllowListDenied(t *testing.T) {
	cfg := baseConfig()
	s := baseSettingsWithProber()
	// Deliberately exclude localhost caller.
	s.ProberClientAllowCIDRs = []string{"10.0.0.0/8"}

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	resp, err := http.Get(baseURL + "/probe?target=127.0.0.1&ports=22")
	if err != nil {
		t.Fatalf("GET /probe: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for client not in allow-list, got %d", resp.StatusCode)
	}
}

func TestProbeTargetNotAllowed(t *testing.T) {
	cfg := baseConfig()
	s := baseSettingsWithProber()
	// Only allow 127.0.0.0/8; then target 8.8.8.8 should be blocked.
	s.ProberAllowCIDRs = []string{"127.0.0.0/8"}

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	resp, err := http.Get(baseURL + "/probe?target=8.8.8.8&ports=22")
	if err != nil {
		t.Fatalf("GET /probe: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for target not in allow-list, got %d", resp.StatusCode)
	}
}

func TestProbePortsValidation(t *testing.T) {
	cfg := baseConfig()
	s := baseSettingsWithProber()

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	// Invalid syntax
	{
		resp, err := http.Get(baseURL + "/probe?target=127.0.0.1&ports=abc-")
		if err != nil {
			t.Fatalf("GET /probe: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid ports syntax, got %d", resp.StatusCode)
		}
	}
	// Out-of-range port
	{
		resp, err := http.Get(baseURL + "/probe?target=127.0.0.1&ports=70000")
		if err != nil {
			t.Fatalf("GET /probe: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for out-of-range ports, got %d", resp.StatusCode)
		}
	}
}

func TestProbeRateLimitingTriggers429(t *testing.T) {
	cfg := baseConfig()
	s := baseSettingsWithProber()
	// Set a very low RPS and small burst to force 429s under a small burst.
	s.ProberRateLimit = 1.0
	s.ProberBurst = 1

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	// Fire a quick burst of requests that don't need to pass later validations (missing target is OK).
	var got429 int
	for i := 0; i < 6; i++ {
		resp, err := http.Get(baseURL + "/probe")
		if err != nil {
			t.Fatalf("GET /probe burst: %v", err)
		}
		// Drain body to allow limiter tokens to be consumed cleanly.
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429++
		}
		// Very short pause to keep within a one-second window.
		time.Sleep(30 * time.Millisecond)
	}

	if got429 == 0 {
		t.Fatalf("expected at least one 429 from rate limiting, got 0")
	}
}

func TestRootPageRenders(t *testing.T) {
	cfg := baseConfig()
	s := baseSettingsWithProber()

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
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), s.MetricsPath) {
		t.Fatalf("root page should mention metrics path %q", s.MetricsPath)
	}
}

func TestScrapeTimeoutHeaderReducesDeadline(t *testing.T) {
	// We cannot directly observe internal deadline, but we can ensure the handler
	// accepts the header and still returns a 400 for missing ports (i.e., request processed).
	cfg := baseConfig()
	s := baseSettingsWithProber()

	baseURL, shutdown := startHTTPServer(t, s, cfg)
	defer shutdown()

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/probe?target=127.0.0.1", nil)
	req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "0.2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /probe with timeout header: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 (missing ports) with timeout header, got %d", resp.StatusCode)
	}
}

// Optional small helper to ensure we aren't accidentally following redirects, etc.
func getRaw(t *testing.T, endpoint string) (int, http.Header, string) {
	t.Helper()
	u, _ := url.Parse(endpoint)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.Path, u.Host)
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	hdrs := http.Header{}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "\n" {
			break
		}
		if i := strings.Index(line, ":"); i > 0 {
			k := line[:i]
			v := strings.TrimSpace(line[i+1:])
			hdrs.Add(k, strings.TrimRight(v, "\r\n"))
		}
	}
	b, _ := io.ReadAll(br)
	_ = status // not parsed here; used by high-level client elsewhere
	return 0, hdrs, string(b)
}
