package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetailTargetsWithoutScheduledOverlap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		targets    []TargetDef
		detail     DetailTarget
		wantMissed bool
	}{
		{
			name: "scheduled subnet contains detail host",
			targets: []TargetDef{{
				Target: "192.168.10.0/24", PortRange: "20-23,443", Protocol: " TCP ",
			}},
			detail: DetailTarget{
				Alias: "ssh", CIDR: "192.168.10.10/32", Protocol: "", Ports: []string{"22"},
			},
		},
		{
			name: "detail subnet contains scheduled host",
			targets: []TargetDef{{
				Target: "192.168.10.10", PortRange: "443", Protocol: "tcp",
			}},
			detail: DetailTarget{
				Alias: "web", CIDR: "192.168.10.0/24", Protocol: "tcp", Ports: []string{"443"},
			},
		},
		{
			name: "issue 14 has no network overlap",
			targets: []TargetDef{{
				Target: "10.140.86.115", PortRange: "1-99", Protocol: "tcp",
			}},
			detail: DetailTarget{
				Alias:    "web-servers-dmz",
				CIDR:     "10.140.86.200/32",
				Protocol: "tcp",
				Ports:    []string{"80"},
			},
			wantMissed: true,
		},
		{
			name: "network overlap without port overlap",
			targets: []TargetDef{{
				Target: "10.0.0.0/24", PortRange: "80,443", Protocol: "tcp",
			}},
			detail: DetailTarget{
				Alias: "ssh", CIDR: "10.0.0.10", Protocol: "tcp", Ports: []string{"22"},
			},
			wantMissed: true,
		},
		{
			name: "network and port overlap without protocol overlap",
			targets: []TargetDef{{
				Target: "10.0.0.0/24", PortRange: "53", Protocol: "udp",
			}},
			detail: DetailTarget{
				Alias: "dns", CIDR: "10.0.0.53", Protocol: "tcp", Ports: []string{"53"},
			},
			wantMissed: true,
		},
		{
			name: "IPv6 overlap",
			targets: []TargetDef{{
				Target: "2001:db8::/64", PortRange: "443", Protocol: "tcp",
			}},
			detail: DetailTarget{
				Alias: "v6-web", CIDR: "2001:db8::10/128", Protocol: "tcp", Ports: []string{"443"},
			},
		},
		{
			name: "IPv4 and IPv6 do not overlap",
			targets: []TargetDef{{
				Target: "2001:db8::/64", PortRange: "443", Protocol: "tcp",
			}},
			detail: DetailTarget{
				Alias: "v4-web", CIDR: "192.0.2.10", Protocol: "tcp", Ports: []string{"443"},
			},
			wantMissed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Targets: test.targets,
				BackgroundDetails: &BackgroundDetailsConfig{
					Enabled: true,
					Targets: []DetailTarget{test.detail},
				},
			}
			missing := cfg.DetailTargetsWithoutScheduledOverlap()
			if test.wantMissed {
				require.Len(t, missing, 1)
				assert.Equal(t, test.detail, missing[0])
				return
			}
			assert.Empty(t, missing)
		})
	}
}

func TestDetailTargetsWithoutScheduledOverlapUsesDefaultPortRange(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Scanning: ScanningConfig{PortRange: "8000-8010"},
		Targets: []TargetDef{{
			Target: "192.0.2.0/24", Protocol: "tcp",
		}},
		BackgroundDetails: &BackgroundDetailsConfig{
			Enabled: true,
			Targets: []DetailTarget{{
				Alias: "service", CIDR: "192.0.2.10", Protocol: "tcp", Ports: []string{"8005"},
			}},
		},
	}

	assert.Empty(t, cfg.DetailTargetsWithoutScheduledOverlap())
}

func TestDetailTargetsWithoutScheduledOverlapIgnoresDisabledDetails(t *testing.T) {
	t.Parallel()

	cfg := &Config{BackgroundDetails: &BackgroundDetailsConfig{
		Enabled: false,
		Targets: []DetailTarget{{Alias: "api-only", CIDR: "192.0.2.10", Ports: []string{"22"}}},
	}}

	assert.Empty(t, cfg.DetailTargetsWithoutScheduledOverlap())

	var nilConfig *Config
	assert.Empty(t, nilConfig.DetailTargetsWithoutScheduledOverlap())
}
