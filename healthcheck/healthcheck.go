package healthcheck

import (
	"fmt"
	"net/http"
	"openport-exporter/config"
	"openport-exporter/scanner"

	"github.com/sirupsen/logrus"
)

// HealthCheckHandler returns a handler that returns a 200 OK response if the task queue is not full.
func HealthCheckHandler(taskQueue chan scanner.ScanTask, cfg *config.Config, log *logrus.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		queueSize := len(taskQueue)
		if queueSize >= cfg.Performance.TaskQueueSize {
			log.WithField("queue_size", queueSize).Warn("task queue is full")
			http.Error(w, "task queue is full", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok", "queue_size": ` + fmt.Sprintf("%d", queueSize) + `}`))
	}
}
