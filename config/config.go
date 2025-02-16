package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

// Config holds the configuration settings.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Scanning    ScanningConfig    `yaml:"scanning"`
	Performance PerformanceConfig `yaml:"performance"`
	Auth        *AuthConfig       `yaml:"auth"`
	Targets     []string          `yaml:"targets"`
}

// ServerConfig holds server-related configurations.
type ServerConfig struct {
	Port int `yaml:"port"`
}

// ScanningConfig holds scanning-related configurations.
type ScanningConfig struct {
	Interval             int    `yaml:"interval"`
	PortRange            string `yaml:"port_range"`
	MaxCIDRSize          int    `yaml:"max_cidr_size"`
	Timeout              int    `yaml:"timeout"`
	DurationMetrics      bool   `yaml:"duration_metrics"`
	DisableDNSResolution bool   `yaml:"disable_dns_resolution"`
	MinRate              int    `yaml:"min_rate"`
	MinParallelism       int    `yaml:"min_parallelism"`
	UDPScan              bool   `yaml:"udp_scan"`
}

// PerformanceConfig holds performance-related configurations.
type PerformanceConfig struct {
	RateLimit     int `yaml:"rate_limit"`
	TaskQueueSize int `yaml:"task_queue_size"`
	WorkerCount   int `yaml:"worker_count"`
}

// AuthConfig holds authentication configurations.
type AuthConfig struct {
	Basic BasicAuthConfig `yaml:"basic"`
}

// BasicAuthConfig holds basic authentication credentials.
type BasicAuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Default constants for fallback values.
const (
	DefaultScanInterval  = 10800
	DefaultScanTimeout   = 3600
	DefaultPortRange     = "1-65535"
	DefaultRateLimit     = 60
	DefaultWorkerCount   = 5
	DefaultTaskQueueSize = 100
	DefaultMaxCIDRSize   = 24
)

// LoadConfig loads the configuration from a YAML file.
func LoadConfig(filename string) (*Config, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.UnmarshalStrict(content, &cfg); err != nil {
		return nil, err
	}
	// Validate server port.
	if cfg.Server.Port < 0 || cfg.Server.Port > 65535 {
		return nil, fmt.Errorf("invalid server port: %d", cfg.Server.Port)
	}
	if cfg.Scanning.Interval < 600 {
		cfg.Scanning.Interval = DefaultScanInterval
	}
	if cfg.Scanning.Timeout <= 0 {
		cfg.Scanning.Timeout = DefaultScanTimeout
	}
	if cfg.Scanning.PortRange == "" {
		cfg.Scanning.PortRange = DefaultPortRange
	}
	if cfg.Performance.RateLimit <= 0 {
		cfg.Performance.RateLimit = DefaultRateLimit
	}
	if cfg.Performance.WorkerCount <= 0 {
		cfg.Performance.WorkerCount = DefaultWorkerCount
	}
	if cfg.Performance.TaskQueueSize <= 0 {
		cfg.Performance.TaskQueueSize = DefaultTaskQueueSize
	}
	if cfg.Scanning.MaxCIDRSize <= 0 || cfg.Scanning.MaxCIDRSize > 128 {
		cfg.Scanning.MaxCIDRSize = DefaultMaxCIDRSize
	}
	return &cfg, nil
}

// GetScanIntervalDuration returns the scan interval as a time.Duration.
func (c *Config) GetScanIntervalDuration() time.Duration {
	return time.Duration(c.Scanning.Interval) * time.Second
}
