package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/renatogalera/openport-exporter/internal/allowlist"
)

// Manager guards the active configuration with an RWMutex and provides
// snapshot semantics for readers.
type Manager struct {
	mu         sync.RWMutex
	cfg        *Config
	configPath string
	// Optional callbacks for post-reload operations (e.g., updating sweeper TTL)
	onReload []func(old, newCfg *Config)

	// Derived state rebuilt on load/reload
	allowCache *allowlist.Cache
}

// NewManager creates a new manager with an initial config and the path it came from.
func NewManager(initial *Config, path string) *Manager {
	m := &Manager{cfg: initial, configPath: filepath.Clean(path)}
	m.recomputeDerivedLocked()
	return m
}

// SetOnReload sets a callback that will be called after each successful reload
// with the old and new configurations. This allows components to react to
// configuration changes (e.g., update TTL, restart services, etc.)
func (m *Manager) SetOnReload(callback func(old, newCfg *Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onReload = nil
	if callback != nil {
		m.onReload = append(m.onReload, callback)
	}
}

// AddOnReload appends a callback to be called on each successful reload.
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
	m.mu.Lock()
	old := m.cfg
	m.cfg = c
	m.recomputeDerivedLocked()
	callbacks := append([]func(old, newCfg *Config){}, m.onReload...)
	m.mu.Unlock()

	// Call the callback outside the lock to avoid deadlocks
	for _, cb := range callbacks {
		if cb != nil {
			cb(old, c)
		}
	}
}

// Reload loads the configuration from the original file path and updates it.
// This centralizes the reload logic for both SIGHUP and /-/reload endpoint.
func (m *Manager) Reload() error {
	newCfg, err := LoadConfig(m.Path())
	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", m.Path(), err)
	}

	m.Update(newCfg)
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

// GetAllowlistCache returns the precomputed allowlist cache (or nil if disabled/empty).
func (m *Manager) GetAllowlistCache() *allowlist.Cache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allowCache
}

// (no prober state; /probe is not supported)

// recomputeDerivedLocked rebuilds derived caches/state. Caller must hold m.mu.
func (m *Manager) recomputeDerivedLocked() {
	// Allowlist cache for background details
	m.allowCache = nil
	if m.cfg != nil && m.cfg.BackgroundDetails != nil && m.cfg.BackgroundDetails.Enabled &&
		len(m.cfg.BackgroundDetails.Targets) > 0 {
		entries := make([]allowlist.Entry, 0, len(m.cfg.BackgroundDetails.Targets))
		for _, t := range m.cfg.BackgroundDetails.Targets {
			e := allowlist.Entry{
				Alias:    t.Alias,
				CIDR:     t.CIDR,
				Protocol: t.Protocol,
				Ports:    append([]string(nil), t.Ports...),
			}
			entries = append(entries, e)
		}
		m.allowCache = allowlist.Build(entries)
	}

	// No prober state
}
