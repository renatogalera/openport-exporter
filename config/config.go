package config

import (
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

	var config Config
	err = yaml.UnmarshalStrict(content, &config)
	if err != nil {
		return nil, err
	}

	// Set defaults if necessary.
	if config.Scanning.Interval <= 600 {
		config.Scanning.Interval = DefaultScanInterval
	}
	if config.Scanning.Timeout <= 0 {
		config.Scanning.Timeout = DefaultScanTimeout
	}
	if config.Scanning.PortRange == "" {
		config.Scanning.PortRange = DefaultPortRange
	}
	if config.Performance.RateLimit <= 0 {
		config.Performance.RateLimit = DefaultRateLimit
	}
	if config.Performance.WorkerCount <= 0 {
		config.Performance.WorkerCount = DefaultWorkerCount
	}
	if config.Performance.TaskQueueSize <= 0 {
		config.Performance.TaskQueueSize = DefaultTaskQueueSize
	}
	if config.Scanning.MaxCIDRSize <= 0 {
		config.Scanning.MaxCIDRSize = DefaultMaxCIDRSize
	}

	return &config, nil
}

// GetScanIntervalDuration returns the scan interval as a time.Duration.
func (c *Config) GetScanIntervalDuration() time.Duration {
	return time.Duration(c.Scanning.Interval) * time.Second
}
