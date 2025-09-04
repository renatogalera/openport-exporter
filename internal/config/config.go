package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the configuration settings.
type Config struct {
	Server            ServerConfig             `yaml:"server"`
	Scanning          ScanningConfig           `yaml:"scanning"`
	Auth              *AuthConfig              `yaml:"auth"`
	Targets           []TargetDef              `yaml:"targets"`
	BackgroundDetails *BackgroundDetailsConfig `yaml:"background_details,omitempty"`
	// New sections per design
	Policy    *PolicyConfig     `yaml:"policy,omitempty"`
	Scheduler *SchedulerConfig  `yaml:"scheduler,omitempty"`
	Modules   map[string]Module `yaml:"modules,omitempty"`
}

// TargetDef defines a background scanning target configuration.
type TargetDef struct {
	Name      string `yaml:"name"`
	Target    string `yaml:"target"`
	PortRange string `yaml:"port_range"`
	Protocol  string `yaml:"protocol"`
	Interval  string `yaml:"interval"` // e.g. "1h"
	Module    string `yaml:"module"`
}

// ServerConfig holds server-related configurations.
type ServerConfig struct {
	Port                int      `yaml:"port"`
	TrustedProxiesCIDRs []string `yaml:"trusted_proxies_cidrs"`
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
	// Controls TCP scan mode: when true (default), use SYN scan (requires CAP_NET_RAW);
	// when false, use TCP connect() scan (no special capability required).
	UseSYNScan *bool `yaml:"use_syn_scan"`

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
	Basic       BasicAuthConfig `yaml:"basic"`
	BearerToken string          `yaml:"bearer_token"`
}

// BasicAuthConfig holds basic authentication credentials.
type BasicAuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Policy for API guards (client allow-list, rate, series guard)
type PolicyConfig struct {
	ClientAllowCIDRs []string `yaml:"client_allow_cidrs"`
	RateLimitRPS     float64  `yaml:"rate_limit_rps"`
	RateBurst        int      `yaml:"rate_burst"`
	MaxConcurrent    int      `yaml:"max_concurrent"`
	SeriesLimit      int      `yaml:"series_limit"`
}

// Scheduler config for background task handling
type SchedulerConfig struct {
	WorkerCount        int            `yaml:"worker_count"`
	TaskQueueSize      int            `yaml:"task_queue_size"`
	DefaultTimeout     string         `yaml:"default_timeout"`       // e.g. "30m"
	DefaultMaxCIDRSize int            `yaml:"default_max_cidr_size"` // e.g. 24
	DedupeTTL          string         `yaml:"dedupe_ttl"`            // e.g. "15m"
	ModuleLimits       map[string]int `yaml:"module_limits"`         // optional per-module concurrency caps
	TaskGCMax          int            `yaml:"task_gc_max"`
	TaskGCMaxAge       string         `yaml:"task_gc_max_age"`
}

// Module defines scanning overrides for on-demand tasks
type Module struct {
	Protocol             *string `yaml:"protocol"`
	Ports                *string `yaml:"ports"`
	UseSYNScan           *bool   `yaml:"use_syn_scan"`
	MinRate              *int    `yaml:"min_rate"`
	MaxRate              *int    `yaml:"max_rate"`
	MinParallelism       *int    `yaml:"min_parallelism"`
	MaxRetries           *int    `yaml:"max_retries"`
	HostTimeout          *int    `yaml:"host_timeout"`
	ScanDelay            *int    `yaml:"scan_delay"`
	MaxScanDelay         *int    `yaml:"max_scan_delay"`
	InitialRttTimeout    *int    `yaml:"initial_rtt_timeout"`
	MaxRttTimeout        *int    `yaml:"max_rtt_timeout"`
	MinRttTimeout        *int    `yaml:"min_rtt_timeout"`
	DisableHostDiscovery *bool   `yaml:"disable_host_discovery"`
}

// --- Background details (opt-in, bounded) ---

type BackgroundDetailsConfig struct {
	Enabled      bool           `yaml:"enabled"`
	SeriesBudget int            `yaml:"series_budget"` // hard cap
	TTL          string         `yaml:"ttl"`           // e.g. "30m"
	Targets      []DetailTarget `yaml:"targets"`

	IncludeAlias bool  `yaml:"include_alias"` // export alias label
	IncludeIP    *bool `yaml:"include_ip"`    // defaults to true
}

type DetailTarget struct {
	Alias    string   `yaml:"alias"`
	CIDR     string   `yaml:"cidr"`     // CIDR or single IP (e.g. 10.0.0.5/32)
	Protocol string   `yaml:"protocol"` // tcp|udp
	Ports    []string `yaml:"ports"`    // e.g. ["22","80","443","1000-1024"]
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
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
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
	// Default UseSYNScan to true if not explicitly set
	if cfg.Scanning.UseSYNScan == nil {
		t := true
		cfg.Scanning.UseSYNScan = &t
	}

	// Background details defaults (safe by default)
	if cfg.BackgroundDetails == nil {
		cfg.BackgroundDetails = &BackgroundDetailsConfig{Enabled: false}
	}
	if cfg.BackgroundDetails.Enabled {
		if cfg.BackgroundDetails.SeriesBudget <= 0 {
			cfg.BackgroundDetails.SeriesBudget = 2000
		}
		if strings.TrimSpace(cfg.BackgroundDetails.TTL) == "" {
			cfg.BackgroundDetails.TTL = "30m"
		}
		if cfg.BackgroundDetails.IncludeIP == nil {
			t := true
			cfg.BackgroundDetails.IncludeIP = &t
		}

		// Validate Background Details targets: alias uniqueness, CIDR/IP and ports syntax
		if err := validateBackgroundDetails(cfg.BackgroundDetails); err != nil {
			return nil, err
		}
	}

	// Validate targets (per-target settings). Targets can be empty for API-only mode.
	// When empty, the exporter starts without background scanning targets.
	// If provided, validate each target below.
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if strings.TrimSpace(t.Target) == "" {
			return nil, fmt.Errorf("targets[%d]: target is required", i)
		}
		// Validate IP or CIDR
		if ip := net.ParseIP(t.Target); ip == nil {
			if _, _, err := net.ParseCIDR(t.Target); err != nil {
				return nil, fmt.Errorf("targets[%d]: invalid target %q", i, t.Target)
			}
		}
		if strings.TrimSpace(t.PortRange) == "" {
			t.PortRange = cfg.Scanning.PortRange
		}
		if !isValidPortsString(t.PortRange) {
			return nil, fmt.Errorf("targets[%d]: invalid port_range %q", i, t.PortRange)
		}
		p := strings.ToLower(strings.TrimSpace(t.Protocol))
		if p == "" {
			p = "tcp"
		}
		if p != "tcp" && p != "udp" {
			return nil, fmt.Errorf("targets[%d]: invalid protocol %q", i, t.Protocol)
		}
		t.Protocol = p
		if strings.TrimSpace(t.Interval) == "" {
			t.Interval = "1h"
		}
		if _, err := time.ParseDuration(t.Interval); err != nil {
			return nil, fmt.Errorf("targets[%d]: invalid interval %q", i, t.Interval)
		}
		// Name optional; default to target for display
		if strings.TrimSpace(t.Name) == "" {
			t.Name = t.Target
		}
	}

	// Policy defaults
	if cfg.Policy == nil {
		cfg.Policy = &PolicyConfig{}
	}
	if cfg.Policy.RateLimitRPS <= 0 {
		cfg.Policy.RateLimitRPS = 2.0
	}
	if cfg.Policy.RateBurst <= 0 {
		cfg.Policy.RateBurst = 2
	}
	if cfg.Policy.MaxConcurrent <= 0 {
		cfg.Policy.MaxConcurrent = 2
	}
	if cfg.Policy.SeriesLimit <= 0 {
		cfg.Policy.SeriesLimit = 250000
	}

	// Scheduler defaults (fallback to scanning where applicable)
	if cfg.Scheduler == nil {
		cfg.Scheduler = &SchedulerConfig{}
	}
	if cfg.Scheduler.WorkerCount <= 0 {
		cfg.Scheduler.WorkerCount = cfg.Scanning.WorkerCount
	}
	if cfg.Scheduler.TaskQueueSize <= 0 {
		cfg.Scheduler.TaskQueueSize = cfg.Scanning.TaskQueueSize
	}
	if strings.TrimSpace(cfg.Scheduler.DefaultTimeout) == "" {
		cfg.Scheduler.DefaultTimeout = "30m"
	}
	if cfg.Scheduler.DefaultMaxCIDRSize <= 0 {
		cfg.Scheduler.DefaultMaxCIDRSize = 24
	}
	if strings.TrimSpace(cfg.Scheduler.DedupeTTL) == "" {
		cfg.Scheduler.DedupeTTL = "15m"
	}
	if cfg.Scheduler.TaskGCMax <= 0 {
		cfg.Scheduler.TaskGCMax = 10000
	}
	if strings.TrimSpace(cfg.Scheduler.TaskGCMaxAge) == "" {
		cfg.Scheduler.TaskGCMaxAge = "24h"
	}

	return &cfg, nil
}

// GetScanIntervalDuration returns the scan interval as a time.Duration.
func (c *Config) GetScanIntervalDuration() time.Duration {
	return time.Duration(c.Scanning.Interval) * time.Second
}

// UseSYNScanEnabled returns the effective value of UseSYNScan (default true when unset).
func (c *Config) UseSYNScanEnabled() bool {
	if c.Scanning.UseSYNScan == nil {
		return true
	}
	return *c.Scanning.UseSYNScan
}

// --- Validation helpers ---

func validateBackgroundDetails(bd *BackgroundDetailsConfig) error {
	aliasSeen := make(map[string]struct{})
	for i, t := range bd.Targets {
		a := strings.TrimSpace(t.Alias)
		if a == "" {
			return fmt.Errorf("background_details.targets[%d]: alias is required", i)
		}
		if _, dup := aliasSeen[a]; dup {
			return fmt.Errorf("background_details.targets: duplicate alias %q", a)
		}
		aliasSeen[a] = struct{}{}

		if err := validateCIDRorIP(t.CIDR); err != nil {
			return fmt.Errorf("background_details.targets[%d]: %w", i, err)
		}
		if err := validatePortsList(t.Ports); err != nil {
			return fmt.Errorf("background_details.targets[%d]: %w", i, err)
		}
		p := strings.ToLower(strings.TrimSpace(t.Protocol))
		if p != "tcp" && p != "udp" && p != "" {
			return fmt.Errorf(
				"background_details.targets[%d]: invalid protocol %q (expected tcp or udp)",
				i,
				t.Protocol,
			)
		}
	}
	return nil
}

func validateCIDRorIP(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("cidr/ip is required")
	}
	// Parse IP or CIDR
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return nil
	}
	if ip := net.ParseIP(s); ip == nil {
		return fmt.Errorf("invalid IP %q", s)
	}
	return nil
}

func validatePortsList(list []string) error {
	if len(list) == 0 {
		return fmt.Errorf("ports list is empty")
	}
	for _, ps := range list {
		ps = strings.TrimSpace(ps)
		if ps == "" {
			return fmt.Errorf("ports list contains empty entry")
		}
		if strings.Contains(ps, "-") {
			parts := strings.SplitN(ps, "-", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid port range %q", ps)
			}
			a, errA := strconv.Atoi(parts[0])
			b, errB := strconv.Atoi(parts[1])
			if errA != nil || errB != nil || a < 1 || b < 1 || a > 65535 || b > 65535 || a > b {
				return fmt.Errorf("invalid port range %q", ps)
			}
		} else {
			p, err := strconv.Atoi(ps)
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("invalid port %q", ps)
			}
		}
	}
	return nil
}

// isValidPortsString validates a single comma-separated list of ports/ranges.
func isValidPortsString(ports string) bool {
	tokens := strings.Split(ports, ",")
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return false
		}
		if strings.Contains(tok, "-") {
			parts := strings.SplitN(tok, "-", 2)
			if len(parts) != 2 {
				return false
			}
			a, errA := strconv.Atoi(parts[0])
			b, errB := strconv.Atoi(parts[1])
			if errA != nil || errB != nil || a < 1 || b < 1 || a > 65535 || b > 65535 || a > b {
				return false
			}
		} else {
			p, err := strconv.Atoi(tok)
			if err != nil || p < 1 || p > 65535 {
				return false
			}
		}
	}
	return true
}
