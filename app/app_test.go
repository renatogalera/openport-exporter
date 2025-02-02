package app

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"openport-exporter/config"
	"openport-exporter/scanner"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func TestSetupLogger(t *testing.T) {
	log := setupLogger()
	if log == nil {
		t.Error("setupLogger() returned nil")
		return
	}
	if _, ok := log.Formatter.(*logrus.JSONFormatter); !ok {
		t.Error("Logger formatter is not JSONFormatter")
	}
}

func TestLoadConfiguration(t *testing.T) {
	configPath := createTempConfig(t)
	defer os.Remove(configPath)

	log := setupLogger()
	cfg, err := loadConfiguration(log, configPath)
	if err != nil {
		t.Errorf("loadConfiguration() returned an error: %v", err)
	}
	if cfg == nil {
		t.Error("loadConfiguration() returned nil config")
	}
}

func TestSetupRateLimiter(t *testing.T) {
	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			RateLimit: 10,
		},
	}
	limiter := setupRateLimiter(cfg)
	if limiter == nil {
		t.Error("setupRateLimiter() returned nil")
	}
	// Test rate limiting
	for i := 0; i < 10; i++ {
		if !limiter.Allow() {
			t.Error("Rate limiter should allow 10 requests")
		}
	}
	if limiter.Allow() {
		t.Error("Rate limiter should not allow 11th request")
	}
}

func TestStartWorkers(t *testing.T) {
	configPath := createTempConfig(t)
	defer os.Remove(configPath)

	reg := prometheus.NewRegistry()
	app, err := NewApp(configPath, reg)
	if err != nil {
		t.Fatalf("Failed to create new app: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app.StartWorkers(ctx)

	// Add a task to the queue
	app.TaskQueue <- scanner.ScanTask{Target: "192.168.1.1", PortRange: "80", Protocol: "tcp"}

	// Wait a short time for workers to process
	time.Sleep(200 * time.Millisecond)

	// Check if the task was processed (queue should be empty)
	if len(app.TaskQueue) != 0 {
		t.Error("Workers did not process the task")
	}
}

// TestSetupHTTPHandlers tests the HTTP handler registration.
func TestSetupHTTPHandlers(t *testing.T) {
	configPath := createTempConfig(t)
	defer os.Remove(configPath)

	reg := prometheus.NewRegistry()
	app, err := NewApp(configPath, reg)
	if err != nil {
		t.Fatalf("Failed to create new app: %v", err)
	}

	// Registra as rotas no mux personalizado (app.Mux)
	app.SetupHTTPHandlers()

	// Testa o endpoint /query
	req, err := http.NewRequest("GET", "/query", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	// Usa o app.Mux ao invés de http.DefaultServeMux
	app.Mux.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	// Testa o endpoint /metrics
	req, err = http.NewRequest("GET", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	// Usa o app.Mux ao invés de http.DefaultServeMux
	app.Mux.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestStartServer(t *testing.T) {
	configPath := createTempConfig(t)
	defer os.Remove(configPath)

	reg := prometheus.NewRegistry()
	app, err := NewApp(configPath, reg)
	if err != nil {
		t.Fatalf("Failed to create new app: %v", err)
	}

	// Configura as rotas para que /metrics esteja disponível
	app.SetupHTTPHandlers()

	// Inicia o servidor em uma goroutine separada
	go func() {
		if err := app.Start(); err != nil {
			t.Errorf("Start returned an error: %v", err)
		}
	}()

	// Dá um tempo para o servidor iniciar
	time.Sleep(200 * time.Millisecond)

	// Recupera a porta escolhida pelo sistema (ephemeral port)
	if app.serverListener == nil {
		t.Fatal("serverListener is nil; server probably failed to start")
	}
	actualPort := app.serverListener.Addr().(*net.TCPAddr).Port

	// Constrói a URL usando strconv.Itoa para converter a porta corretamente
	url := "http://localhost:" + strconv.Itoa(actualPort) + "/metrics"
	resp, err := http.Get(url)
	if err != nil {
		t.Errorf("Failed to connect to server: %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Unexpected status code: got %v want %v", resp.StatusCode, http.StatusOK)
		}
	}
}

// createTempConfig writes a minimal YAML config with ephemeral port (0).
func createTempConfig(t *testing.T) string {
	content := `
server:
  port: 0  # Use ephemeral port for testing
scanning:
  interval: 3600
  port_range: "1-1000"
performance:
  rate_limit: 30
  task_queue_size: 50
  worker_count: 3
`
	tmpfile, err := os.CreateTemp("", "config_*.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	return tmpfile.Name()
}

// TestMain resets the default Prometheus registry before/after the test suite.
func TestMain(m *testing.M) {
	// Setup: override the default registry
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	code := m.Run()
	// Teardown
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	os.Exit(code)
}
