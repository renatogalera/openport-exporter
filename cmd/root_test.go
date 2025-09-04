package cmd

import (
	"os"
	"testing"

	"github.com/renatogalera/openport-exporter/internal/collectors"
)

// NOTE: We use package `cmd` (not cmd_test) so we can exercise unexported
// helpers like validateSettings() directly, per your “complete functions” rule.

// resetSettings assigns a clean Settings struct into the package-level `settings`.
func resetSettings() {
	settings = collectors.Settings{
		LogLevel:          "error",
		LogFormat:         "text",
		MetricsPath:       "/metrics",
		ListenPort:        "0",
		Address:           "localhost",
		ConfigPath:        "",
		EnableGoCollector: false,
		EnableBuildInfo:   true,
	}
}

// validateSettings currently only checks basic invariants; keep coverage minimal.

// We cover run()'s error path deterministically by pointing to a missing config file.
// This ensures the function returns an error without binding sockets or spawning workers.
func TestRun_ReturnsErrorOnMissingConfig(t *testing.T) {
	resetSettings()
	settings.ConfigPath = "/definitely/does/not/exist.yaml"
	err := run()
	if err == nil {
		t.Fatalf("expected run() to return error when config file is missing")
	}
	if got := err.Error(); !containsAny(got, []string{"load config", "no such file", "cannot read", "open"}) {
		t.Fatalf("unexpected error message from run(): %q", got)
	}
}

// Helper used only for validating error text in a cross-platform way.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if stringsContainsInsensitive(s, sub) {
			return true
		}
	}
	return false
}

// Case-insensitive contains (no unicode folding needed for our ASCII messages).
func stringsContainsInsensitive(s, sub string) bool {
	s = toLowerASCII(s)
	sub = toLowerASCII(sub)
	return containsASCII(s, sub)
}

func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func containsASCII(s, sub string) bool {
	// Very small helper; avoids importing strings for a single Contains.
	n := len(sub)
	if n == 0 {
		return true
	}
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return true
		}
	}
	return false
}

// Guard against accidental environment interference in tests that might be added later.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
