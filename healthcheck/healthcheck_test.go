package healthcheck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/renatogalera/openport-exporter/config"
	"github.com/renatogalera/openport-exporter/scanner"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// TestHealthCheckHandlerOK tests the health check handler
// when everything is ok.
func TestHealthCheckHandlerOK(t *testing.T) {
	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			TaskQueueSize: 10,
		},
	}
	log := logrus.New()
	taskQueue := make(chan scanner.ScanTask, 10)

	handler := HealthCheckHandler(taskQueue, cfg, log)

	req, err := http.NewRequest("GET", "/healthcheck", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, "ok", response["status"])
	assert.Equal(t, float64(0), response["queue_size"])
}

// TestHealthCheckHandlerQueueEmpty tests the health check handler
// when the task queue is empty
func TestHealthCheckHandlerQueueFull(t *testing.T) {
	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			TaskQueueSize: 2,
		},
	}
	log := logrus.New()
	taskQueue := make(chan scanner.ScanTask, 2)
	taskQueue <- scanner.ScanTask{}
	taskQueue <- scanner.ScanTask{}

	handler := HealthCheckHandler(taskQueue, cfg, log)

	req, err := http.NewRequest("GET", "/healthcheck", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), "task queue is full")
}

// TestHealthCheckHandlerPartiallyFull tests the health check handler
// when the task queue is partially full
func TestHealthCheckHandlerPartiallyFull(t *testing.T) {
	cfg := &config.Config{
		Performance: config.PerformanceConfig{
			TaskQueueSize: 3,
		},
	}
	log := logrus.New()
	taskQueue := make(chan scanner.ScanTask, 3)
	taskQueue <- scanner.ScanTask{}

	handler := HealthCheckHandler(taskQueue, cfg, log)

	req, err := http.NewRequest("GET", "/healthcheck", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, "ok", response["status"])
	assert.Equal(t, float64(1), response["queue_size"])
}
