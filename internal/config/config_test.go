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

func TestManagerDetailsRevisionChangesOnlyForRuntimeRelevantSettings(t *testing.T) {
	includeIP := true
	initial := &Config{BackgroundDetails: &BackgroundDetailsConfig{
		Enabled:      true,
		SeriesBudget: 10,
		TTL:          "30m",
		IncludeAlias: true,
		IncludeIP:    &includeIP,
		Targets: []DetailTarget{{
			Alias:    "ssh",
			CIDR:     "192.168.1.10/32",
			Protocol: "tcp",
			Ports:    []string{"22"},
		}},
	}}
	mgr := NewManager(initial, "config.yaml")
	initialRevision := mgr.Get().DetailsRevision()
	if initialRevision == 0 {
		t.Fatal("expected an initialized details revision")
	}

	ttlOnly := cloneConfigForDetailsTest(initial)
	ttlOnly.BackgroundDetails.TTL = "1h"
	mgr.Update(ttlOnly)
	if got := mgr.Get().DetailsRevision(); got != initialRevision {
		t.Fatalf("TTL-only reload changed details revision: want %d, got %d", initialRevision, got)
	}

	budgetOnly := cloneConfigForDetailsTest(ttlOnly)
	budgetOnly.BackgroundDetails.SeriesBudget = 5
	mgr.Update(budgetOnly)
	budgetRevision := mgr.Get().DetailsRevision()
	if budgetRevision != initialRevision {
		t.Fatalf(
			"budget-only reload changed details revision: want %d, got %d",
			initialRevision,
			budgetRevision,
		)
	}
	if DetailedSeriesDefinitionChanged(ttlOnly, budgetOnly) {
		t.Fatal("budget-only reload must preserve the detailed label definition")
	}

	aliasChange := cloneConfigForDetailsTest(budgetOnly)
	aliasChange.BackgroundDetails.Targets[0].Alias = "renamed-ssh"
	mgr.Update(aliasChange)
	if got := mgr.Get().DetailsRevision(); got != initialRevision+1 {
		t.Fatalf("alias reload revision: want %d, got %d", initialRevision+1, got)
	}
	if !DetailedSeriesDefinitionChanged(budgetOnly, aliasChange) {
		t.Fatal("alias reload must invalidate the detailed label definition")
	}

	intervalOnly := cloneConfigForDetailsTest(aliasChange)
	intervalOnly.Targets = []TargetDef{{
		Target: "192.168.1.0/24", PortRange: "22", Protocol: "tcp", Interval: "24h",
	}}
	baselineTopology := cloneConfigForDetailsTest(intervalOnly)
	baselineTopology.Targets[0].Interval = "1h"
	if DetailedSeriesDefinitionChanged(baselineTopology, intervalOnly) {
		t.Fatal("interval-only reload must update TTL policy without clearing detailed state")
	}

	topologyChange := cloneConfigForDetailsTest(intervalOnly)
	topologyChange.Targets = append([]TargetDef(nil), intervalOnly.Targets...)
	topologyChange.Targets[0].Target = "192.168.2.0/24"
	if !DetailedSeriesDefinitionChanged(intervalOnly, topologyChange) {
		t.Fatal("scan source topology change must invalidate detailed ownership")
	}

	shardChange := cloneConfigForDetailsTest(intervalOnly)
	shardChange.Scanning.MaxCIDRSize++
	if !DetailedSeriesDefinitionChanged(intervalOnly, shardChange) {
		t.Fatal("shard topology change must invalidate detailed ownership")
	}

	disabledTopology := cloneConfigForDetailsTest(intervalOnly)
	disabledTopology.BackgroundDetails.Enabled = false
	disabledTopologyChange := cloneConfigForDetailsTest(disabledTopology)
	disabledTopologyChange.Targets = append([]TargetDef(nil), disabledTopology.Targets...)
	disabledTopologyChange.Targets[0].PortRange = "22,443"
	if !DetailedSeriesDefinitionChanged(disabledTopology, disabledTopologyChange) {
		t.Fatal("scan source topology must advance lifecycle generation while details are disabled")
	}
}

func TestManagerPreparesReloadBeforePublishingScanSnapshot(t *testing.T) {
	includeIP := true
	initial := &Config{BackgroundDetails: &BackgroundDetailsConfig{
		Enabled:      true,
		IncludeAlias: true,
		IncludeIP:    &includeIP,
		Targets: []DetailTarget{{
			Alias: "old", CIDR: "192.168.1.10/32", Protocol: "tcp", Ports: []string{"22"},
		}},
	}}
	mgr := NewManager(initial, "config.yaml")
	next := cloneConfigForDetailsTest(initial)
	next.BackgroundDetails.Targets[0].Alias = "new"

	visibleAlias := ""
	mgr.SetOnReload(func(_, pending *Config) {
		if pending.BackgroundDetails.Targets[0].Alias != "new" {
			t.Fatalf("callback received unexpected pending config")
		}
		visible, _ := mgr.GetScanSnapshot()
		visibleAlias = visible.BackgroundDetails.Targets[0].Alias
	})
	mgr.Update(next)

	if visibleAlias != "old" {
		t.Fatalf("reload published before callbacks completed: saw %q", visibleAlias)
	}
	visible, cache := mgr.GetScanSnapshot()
	if visible.BackgroundDetails.Targets[0].Alias != "new" {
		t.Fatalf("new snapshot was not published after callback")
	}
	if alias, ok := cache.Lookup("192.168.1.10", "22", "tcp"); !ok || alias != "new" {
		t.Fatalf("config/cache snapshot mismatch: alias=%q allowed=%v", alias, ok)
	}
}

func TestLoadConfigBackgroundDetailsTTLDefaultAndValidation(t *testing.T) {
	valid := `
server:
  port: 8080
scanning:
  interval: 3600
background_details:
  enabled: true
  series_budget: 10
  targets:
    - alias: ssh
      cidr: 192.168.1.10/32
      protocol: tcp
      ports: ["22"]
`
	cfg := loadConfigContent(t, valid)
	if cfg.BackgroundDetails.TTL != "30m" {
		t.Fatalf("background details TTL default: want 30m, got %q", cfg.BackgroundDetails.TTL)
	}

	invalid := valid + "  ttl: not-a-duration\n"
	path := writeConfigContent(t, invalid)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected invalid background details TTL to fail config loading")
	}
}

func cloneConfigForDetailsTest(source *Config) *Config {
	clone := *source
	if source.BackgroundDetails == nil {
		return &clone
	}
	details := *source.BackgroundDetails
	if source.BackgroundDetails.IncludeIP != nil {
		includeIP := *source.BackgroundDetails.IncludeIP
		details.IncludeIP = &includeIP
	}
	details.Targets = append([]DetailTarget(nil), source.BackgroundDetails.Targets...)
	for i := range details.Targets {
		details.Targets[i].Ports = append([]string(nil), details.Targets[i].Ports...)
	}
	clone.BackgroundDetails = &details
	return &clone
}

func loadConfigContent(t *testing.T, content string) *Config {
	t.Helper()
	cfg, err := LoadConfig(writeConfigContent(t, content))
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	return cfg
}

func writeConfigContent(t *testing.T, content string) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatalf("create config: %v", err)
	}
	if _, err := file.WriteString(content); err != nil {
		_ = file.Close()
		t.Fatalf("write config: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close config: %v", err)
	}
	return file.Name()
}
