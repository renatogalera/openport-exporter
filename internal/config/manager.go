package config

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/renatogalera/openport-exporter/internal/allowlist"
)

// Manager guards the active configuration with an RWMutex and provides
// snapshot semantics for readers.
type Manager struct {
	mu         sync.RWMutex
	updateMu   sync.Mutex
	cfg        *Config
	configPath string
	// Optional callbacks that prepare reload-aware components before publication.
	onReload []func(old, newCfg *Config)

	// Derived state rebuilt on load/reload
	allowCache      *allowlist.Cache
	detailsRevision uint64
}

// NewManager creates a new manager with an initial config and the path it came from.
func NewManager(initial *Config, path string) *Manager {
	m := &Manager{cfg: initial, configPath: filepath.Clean(path), detailsRevision: 1}
	if initial != nil {
		initial.detailsRevision = m.detailsRevision
	}
	m.recomputeDerivedLocked()
	return m
}

// SetOnReload sets a callback that prepares a new configuration before it is
// published to readers. Callbacks receive the old and pending snapshots and
// must not assume Manager.Get already returns newCfg.
func (m *Manager) SetOnReload(callback func(old, newCfg *Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onReload = nil
	if callback != nil {
		m.onReload = append(m.onReload, callback)
	}
}

// AddOnReload appends a callback that prepares each successful reload.
func (m *Manager) AddOnReload(callback func(old, newCfg *Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if callback != nil {
		m.onReload = append(m.onReload, callback)
	}
}

// Get returns a copy-by-value snapshot of the current config for safe read-only use.
func (m *Manager) Get() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m.cfg
}

// Update replaces the current config. Callers must ensure the config was validated.
func (m *Manager) Update(c *Config) {
	m.updateMu.Lock()
	defer m.updateMu.Unlock()
	m.updateLocked(c)
}

func (m *Manager) updateLocked(c *Config) {
	m.mu.Lock()
	old := m.cfg
	if DetailedSeriesDefinitionChanged(old, c) {
		m.detailsRevision++
	}
	c.detailsRevision = m.detailsRevision
	callbacks := append([]func(old, newCfg *Config){}, m.onReload...)
	m.mu.Unlock()

	// Prepare all reload-aware components before publishing the new snapshot.
	// This prevents workers from observing a generation whose metric policy and
	// allowlist cache have not been installed yet.
	for _, cb := range callbacks {
		if cb != nil {
			cb(old, c)
		}
	}

	m.mu.Lock()
	m.cfg = c
	m.allowCache = buildAllowlistCache(c)
	m.mu.Unlock()
}

// Reload loads the configuration from the original file path and updates it.
// This centralizes the reload logic for both SIGHUP and /-/reload endpoint.
func (m *Manager) Reload() error {
	m.updateMu.Lock()
	defer m.updateMu.Unlock()

	newCfg, err := LoadConfig(m.Path())
	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", m.Path(), err)
	}

	m.updateLocked(newCfg)
	return nil
}

// Path returns the source path (useful for SIGHUP reload).
func (m *Manager) Path() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.configPath
}

// calculateTTL is a helper function to calculate the effective TTL for metrics sweeping
func calculateTTL(cfg *Config) time.Duration {
	ttl := 3 * cfg.GetScanIntervalDuration()
	if cfg.BackgroundDetails != nil && strings.TrimSpace(cfg.BackgroundDetails.TTL) != "" {
		if d, err := time.ParseDuration(cfg.BackgroundDetails.TTL); err == nil && d > 0 {
			ttl = d
		}
	}
	return ttl
}

// GetTTL returns the calculated TTL for the current configuration
func (m *Manager) GetTTL() time.Duration {
	cfg := m.Get()
	return calculateTTL(&cfg)
}

// TTLForConfig exposes the TTL calculation for external callers (e.g., reload callbacks)
func TTLForConfig(c *Config) time.Duration { return calculateTTL(c) }

// DetailedSeriesDefinitionChanged reports whether scan-source identity or
// exported detail labels changed and the lifecycle generation must advance.
// Intervals, budget, and TTL are live policies that preserve the generation.
func DetailedSeriesDefinitionChanged(old, next *Config) bool {
	return !reflect.DeepEqual(
		detailedSeriesDefinitionForConfig(old),
		detailedSeriesDefinitionForConfig(next),
	)
}

func backgroundDetailsFrom(cfg *Config) BackgroundDetailsConfig {
	if cfg == nil || cfg.BackgroundDetails == nil {
		return BackgroundDetailsConfig{}
	}
	return *cfg.BackgroundDetails
}

type detailedSeriesDefinition struct {
	Details     BackgroundDetailsConfig
	MaxCIDRSize int
	Sources     []detailedSourceDefinition
}

type detailedSourceDefinition struct {
	Target    string
	PortRange string
	Protocol  string
}

func detailedSeriesDefinitionForConfig(cfg *Config) detailedSeriesDefinition {
	details := backgroundDetailsFrom(cfg)
	details.SeriesBudget = 0
	details.TTL = ""
	definition := detailedSeriesDefinition{Details: details}
	if cfg == nil {
		return definition
	}
	definition.MaxCIDRSize = cfg.Scanning.MaxCIDRSize
	definition.Sources = make([]detailedSourceDefinition, 0, len(cfg.Targets))
	for _, source := range cfg.Targets {
		definition.Sources = append(definition.Sources, detailedSourceDefinition{
			Target:    strings.TrimSpace(source.Target),
			PortRange: strings.TrimSpace(source.PortRange),
			Protocol:  strings.ToLower(strings.TrimSpace(source.Protocol)),
		})
	}
	sort.Slice(definition.Sources, func(i, j int) bool {
		left, right := definition.Sources[i], definition.Sources[j]
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		if left.PortRange != right.PortRange {
			return left.PortRange < right.PortRange
		}
		return left.Protocol < right.Protocol
	})
	return definition
}

// GetAllowlistCache returns the precomputed allowlist cache (or nil if disabled/empty).
func (m *Manager) GetAllowlistCache() *allowlist.Cache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allowCache
}

// GetScanSnapshot returns a configuration and its matching immutable allowlist
// cache under one read lock so workers cannot combine two reload generations.
func (m *Manager) GetScanSnapshot() (Config, *allowlist.Cache) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m.cfg, m.allowCache
}

// (no prober state; /probe is not supported)

// recomputeDerivedLocked rebuilds derived caches/state. Caller must hold m.mu.
func (m *Manager) recomputeDerivedLocked() {
	m.allowCache = buildAllowlistCache(m.cfg)
}

func buildAllowlistCache(cfg *Config) *allowlist.Cache {
	if cfg != nil && cfg.BackgroundDetails != nil && cfg.BackgroundDetails.Enabled &&
		len(cfg.BackgroundDetails.Targets) > 0 {
		entries := make([]allowlist.Entry, 0, len(cfg.BackgroundDetails.Targets))
		for _, t := range cfg.BackgroundDetails.Targets {
			e := allowlist.Entry{
				Alias:    t.Alias,
				CIDR:     t.CIDR,
				Protocol: t.Protocol,
				Ports:    append([]string(nil), t.Ports...),
			}
			entries = append(entries, e)
		}
		return allowlist.Build(entries)
	}
	return nil
}
