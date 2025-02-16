package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

// Config holds the configuration settings.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Scanning ScanningConfig `yaml:"scanning"`
	Auth     *AuthConfig    `yaml:"auth"`
	Targets  []string       `yaml:"targets"`
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
	UDPScan              bool   `yaml:"udp_scan"`

	// Nmap Performance Tuning Options
	RateLimit            int  `yaml:"rate_limit"`
	TaskQueueSize        int  `yaml:"task_queue_size"`
	WorkerCount          int  `yaml:"worker_count"`
	MinRate              int  `yaml:"min_rate"`               // Minimum packets per second to send
	MaxRate              int  `yaml:"max_rate"`               // Maximum packets per second to send
	MinParallelism       int  `yaml:"min_parallelism"`        // Minimum number of probes to send in parallel
	MaxRetries           int  `yaml:"max_retries"`            // Max port scan probe retransmissions
	HostTimeout          int  `yaml:"host_timeout"`           // Give up on target after this long in seconds
	ScanDelay            int  `yaml:"scan_delay"`             // Delay between probes in milliseconds
	MaxScanDelay         int  `yaml:"max_scan_delay"`         // Maximum delay to adjust to in milliseconds
	InitialRttTimeout    int  `yaml:"initial_rtt_timeout"`    // Initial RTT timeout in milliseconds
	MaxRttTimeout        int  `yaml:"max_rtt_timeout"`        // Maximum RTT timeout in milliseconds
	MinRttTimeout        int  `yaml:"min_rtt_timeout"`        // Minimum RTT timeout in milliseconds
	DisableHostDiscovery bool `yaml:"disable_host_discovery"` // Skip host discovery (equivalent to -Pn)
}

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

	// Default Nmap Performance Tuning Values
	DefaultMinRate              = 1000
	DefaultMinParallelism       = 1000
	DefaultMaxRetries           = 6
	DefaultHostTimeout          = 300 // 5 minutes
	DefaultScanDelay            = 0
	DefaultMaxScanDelay         = 0
	DefaultInitialRttTimeout    = 0
	DefaultMaxRttTimeout        = 0
	DefaultMinRttTimeout        = 0
	DefaultDisableHostDiscovery = true // Default to Pn for faster scanning in known environments
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
	if cfg.Scanning.RateLimit <= 0 {
		cfg.Scanning.RateLimit = DefaultRateLimit
	}
	if cfg.Scanning.WorkerCount <= 0 {
		cfg.Scanning.WorkerCount = DefaultWorkerCount
	}
	if cfg.Scanning.TaskQueueSize <= 0 {
		cfg.Scanning.TaskQueueSize = DefaultTaskQueueSize
	}
	if cfg.Scanning.MaxCIDRSize <= 0 || cfg.Scanning.MaxCIDRSize > 128 {
		cfg.Scanning.MaxCIDRSize = DefaultMaxCIDRSize
	}

	// Apply default values for Nmap performance options if not set.
	if cfg.Scanning.MinRate <= 0 {
		cfg.Scanning.MinRate = DefaultMinRate
	}
	if cfg.Scanning.MinParallelism <= 0 {
		cfg.Scanning.MinParallelism = DefaultMinParallelism
	}
	if cfg.Scanning.MaxRetries < 0 {
		cfg.Scanning.MaxRetries = DefaultMaxRetries
	}
	if cfg.Scanning.HostTimeout <= 0 {
		cfg.Scanning.HostTimeout = DefaultHostTimeout
	}
	if cfg.Scanning.ScanDelay < 0 {
		cfg.Scanning.ScanDelay = DefaultScanDelay
	}
	if cfg.Scanning.MaxScanDelay < 0 {
		cfg.Scanning.MaxScanDelay = DefaultMaxScanDelay
	}
	if cfg.Scanning.InitialRttTimeout < 0 {
		cfg.Scanning.InitialRttTimeout = DefaultInitialRttTimeout
	}
	if cfg.Scanning.MaxRttTimeout < 0 {
		cfg.Scanning.MaxRttTimeout = DefaultMaxRttTimeout
	}
	if cfg.Scanning.MinRttTimeout < 0 {
		cfg.Scanning.MinRttTimeout = DefaultMinRttTimeout
	}
	// Default for DisableHostDiscovery is already set in constant

	return &cfg, nil
}

// GetScanIntervalDuration returns the scan interval as a time.Duration.
func (c *Config) GetScanIntervalDuration() time.Duration {
	return time.Duration(c.Scanning.Interval) * time.Second
}
