package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	content := `
server:
  port: 8080
scanning:
  interval: 3600
  port_range: "1-1000"
  max_cidr_size: 24
  timeout: 1800
  duration_metrics: true
  disable_dns_resolution: false
  min_rate: 500
  min_parallelism: 5
  rate_limit: 30
  task_queue_size: 50
  worker_count: 3
auth:
  basic:
    username: testuser
    password: testpass
targets:
  - name: t1
    target: 192.168.1.1/24
    port_range: "1-1000"
    protocol: tcp
    interval: "1h"
  - name: t2
    target: 10.0.0.0/16
    port_range: "1-1000"
    protocol: tcp
    interval: "2h"
`
	tmpfile, err := os.CreateTemp("", "config_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test LoadConfig
	config, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check if the config is loaded correctly
	if config.Server.Port != 8080 {
		t.Errorf("Expected Server.Port to be 8080, got %d", config.Server.Port)
	}
	if config.Scanning.Interval != 3600 {
		t.Errorf("Expected Scanning.Interval to be 3600, got %d", config.Scanning.Interval)
	}
	if config.Scanning.PortRange != "1-1000" {
		t.Errorf("Expected Scanning.PortRange to be '1-1000', got %s", config.Scanning.PortRange)
	}
	if config.Scanning.RateLimit != 30 {
		t.Errorf("Expected Performance.RateLimit to be 30, got %d", config.Scanning.RateLimit)
	}
	if config.Auth.Basic.Username != "testuser" {
		t.Errorf("Expected Auth.Basic.Username to be 'testuser', got %s", config.Auth.Basic.Username)
	}
	if len(config.Targets) != 2 {
		t.Errorf("Expected 2 targets, got %d", len(config.Targets))
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	// Create a temporary config file with minimal configuration
	content := `
server:
  port: 8080
targets:
  - name: t1
    target: 127.0.0.1/32
    port_range: "22"
    protocol: tcp
    interval: "1h"
`
	tmpfile, err := os.CreateTemp("", "config_test_defaults")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test LoadConfig
	config, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check if default values are set correctly
	if config.Scanning.Interval != DefaultScanInterval {
		t.Errorf(
			"Expected default Scanning.Interval to be %d, got %d",
			DefaultScanInterval,
			config.Scanning.Interval,
		)
	}
	if config.Scanning.Timeout != DefaultScanTimeout {
		t.Errorf(
			"Expected default Scanning.Timeout to be %d, got %d",
			DefaultScanTimeout,
			config.Scanning.Timeout,
		)
	}
	if config.Scanning.PortRange != DefaultPortRange {
		t.Errorf(
			"Expected default Scanning.PortRange to be '%s', got '%s'",
			DefaultPortRange,
			config.Scanning.PortRange,
		)
	}
	if config.Scanning.RateLimit != DefaultRateLimit {
		t.Errorf(
			"Expected default Performance.RateLimit to be %d, got %d",
			DefaultRateLimit,
			config.Scanning.RateLimit,
		)
	}
}

func TestGetScanIntervalDuration(t *testing.T) {
	config := &Config{
		Scanning: ScanningConfig{
			Interval: 3600,
		},
	}

	expected := 1 * time.Hour
	actual := config.GetScanIntervalDuration()

	if actual != expected {
		t.Errorf("Expected duration to be %v, got %v", expected, actual)
	}
}
