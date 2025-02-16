package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/renatogalera/openport-exporter/config"
	"github.com/renatogalera/openport-exporter/metrics"

	"github.com/Ullaakut/nmap"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

func TestSplitIntoSubnets(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		maxCIDRSize int
		expected    []string
		expectErr   bool
	}{
		{
			name:        "Single IP",
			target:      "192.168.1.1",
			maxCIDRSize: 24,
			expected:    []string{"192.168.1.1"},
		},
		{
			name:        "IPv4 CIDR within max size",
			target:      "192.168.1.0/24",
			maxCIDRSize: 24,
			expected:    []string{"192.168.1.0/24"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := splitIntoSubnets(tt.target, tt.maxCIDRSize)
			if (err != nil) != tt.expectErr {
				t.Fatalf("Expected error: %v, got: %v", tt.expectErr, err)
			}
			if !tt.expectErr && !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected: %v, got: %v", tt.expected, result)
			}
		})
	}
}

func TestEnqueueScanTask(t *testing.T) {
	ctx := context.Background()
	taskQueue := make(chan ScanTask, 10)
	defer close(taskQueue)

	err := EnqueueScanTask(ctx, taskQueue, "192.168.1.0/24", "80", "tcp", 24)
	if err != nil {
		t.Fatalf("Failed to enqueue scan task: %v", err)
	}

	expectedTasks := 1
	actualTasks := len(taskQueue)
	if actualTasks != expectedTasks {
		t.Errorf("Expected %d tasks, got %d", expectedTasks, actualTasks)
	}
}

func TestHandleQuery(t *testing.T) {
	cfg := &config.Config{
		Scanning: config.ScanningConfig{
			Interval:        10,
			MaxCIDRSize:     24,
			DurationMetrics: true,
		},
		Performance: config.PerformanceConfig{
			RateLimit: 5,
		},
	}
	rateLimiter := rate.NewLimiter(5, 1)
	log := logrus.New()
	taskQueue := make(chan ScanTask, 10)
	metricsCollector := metrics.NewMetricsCollector()
	handler := HandleQuery(cfg, rateLimiter, log, taskQueue, metricsCollector)

	req, err := http.NewRequest("GET", "/query?ip=192.168.1.1&ports=80", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", w.Code)
	}
}

func TestProcessNmapResults(t *testing.T) {
	// Mock data
	result := &nmap.Run{
		Hosts: []nmap.Host{
			{
				Addresses: []nmap.Address{
					{Addr: "192.168.1.1"},
				},
				Ports: []nmap.Port{
					{
						ID:    80,
						State: nmap.State{State: "open"},
					},
					{
						ID:    22,
						State: nmap.State{State: "closed"},
					},
				},
			},
		},
	}

	task := ScanTask{
		Target:    "192.168.1.1",
		PortRange: "22-80",
		Protocol:  "tcp",
	}

	expectedResults := map[string]struct{}{
		"192.168.1.1:80": {},
	}

	// Now we capture all three returned values
	gotResults, gotUp, gotDown := processNmapResults(result, task, logrus.New())

	if !reflect.DeepEqual(gotResults, expectedResults) {
		t.Errorf("Expected %v, got %v", expectedResults, gotResults)
	}

	// Expect 1 host up, 0 down
	if gotUp != 1 {
		t.Errorf("Expected 1 host up, got %d", gotUp)
	}
	if gotDown != 0 {
		t.Errorf("Expected 0 hosts down, got %d", gotDown)
	}
}

func TestCreateNmapScanner(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{
		Scanning: config.ScanningConfig{
			DisableDNSResolution: true,
			MinRate:              100,
			MinParallelism:       10,
		},
	}

	task := ScanTask{
		Target:    "192.168.1.1",
		PortRange: "80",
		Protocol:  "tcp",
	}

	scanner, err := createNmapScanner(task, cfg, ctx)
	if err != nil {
		t.Fatalf("Failed to create Nmap scanner: %v", err)
	}

	if scanner == nil {
		t.Error("Expected scanner to be non-nil")
	}
}
