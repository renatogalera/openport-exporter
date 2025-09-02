package scanner

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"

	"github.com/Ullaakut/nmap/v3"
)

// --- helpers ---

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- splitIntoSubnets / IPv4/IPv6 ---

func TestSplitIntoSubnets_IPv4_SingleIP(t *testing.T) {
	got, err := splitIntoSubnets("192.0.2.1", 24)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.0.2.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestSplitIntoSubnets_IPv4_WithinMax_NoSplit(t *testing.T) {
	got, err := splitIntoSubnets("192.0.2.0/24", 24)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.0.2.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestSplitIntoSubnets_IPv4_SplitIntoQuarters(t *testing.T) {
	// /24 split to /26 => 4 subnets
	got, err := splitIntoSubnets("10.1.2.0/24", 26)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 subnets, got %d: %v", len(got), got)
	}
	for _, s := range got {
		if !endsWith(s, "/26") {
			t.Fatalf("expected each subnet to be /26, got %q", s)
		}
	}
}

func TestSplitIntoSubnets_IPv4_MaxLessThanOnes_NoMerge(t *testing.T) {
	// ones=24, max=16 => função não pode "agregar"; retorna a CIDR original.
	got, err := splitIntoSubnets("172.16.5.0/24", 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"172.16.5.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestSplitIntoSubnets_IPv6_NoSplit(t *testing.T) {
	got, err := splitIntoSubnets("2001:db8::/64", 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"2001:db8::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestSplitIntoSubnets_IPv6_SplitSmall(t *testing.T) {
	// /126 -> /128 => 4 subnets (endereços individuais)
	got, err := splitIntoSubnets("2001:db8::/126", 128)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 subnets, got %d: %v", len(got), got)
	}
	for _, s := range got {
		if !endsWith(s, "/128") {
			t.Fatalf("expected /128 leafs, got %q", s)
		}
	}
}

func TestSplitIntoSubnets_InvalidTarget_Error(t *testing.T) {
	if _, err := splitIntoSubnets("not-an-ip", 24); err == nil {
		t.Fatalf("expected error for invalid target")
	}
}

// --- EnqueueScanTask ---

func TestEnqueueScanTask_OK(t *testing.T) {
	ctx := context.Background()
	ch := make(chan ScanTask, 8)

	if err := EnqueueScanTask(ctx, ch, "192.168.10.0/24", "80,443", "tcp", 26); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /24 -> /26 => 4 tasks
	if got := len(ch); got != 4 {
		t.Fatalf("want 4 tasks, got %d", got)
	}
}

func TestEnqueueScanTask_PreCanceledContext_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := make(chan ScanTask, 8)

	if err := EnqueueScanTask(ctx, ch, "192.168.1.0/24", "80", "tcp", 26); err == nil {
		t.Fatalf("expected error when context is canceled before enqueue")
	}
	if got := len(ch); got != 0 {
		t.Fatalf("queue should be empty, got %d", got)
	}
}

// --- processNmapResults ---

func TestProcessNmapResults_OpenClosedAndCounts(t *testing.T) {
	res := &nmap.Run{
		Hosts: []nmap.Host{
			{
				Status:    nmap.Status{State: "up"},
				Addresses: []nmap.Address{{Addr: "192.168.1.10"}},
				Ports: []nmap.Port{
					{ID: 80, State: nmap.State{State: "open"}},
					{ID: 22, State: nmap.State{State: "closed"}},
				},
			},
			{
				Status:    nmap.Status{State: "down"},
				Addresses: []nmap.Address{{Addr: "192.168.1.11"}},
				Ports:     []nmap.Port{},
			},
		},
	}
	task := ScanTask{Target: "192.168.1.0/24", PortRange: "22,80", Protocol: "tcp"}

	got, up, down := processNmapResults(res, task, silentLogger())
	want := map[string]struct{}{"192.168.1.10:80/tcp": {}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	if up != 1 || down != 1 {
		t.Fatalf("want up=1, down=1, got up=%d down=%d", up, down)
	}
}

func TestProcessNmapResults_IPv6KeyFormatting(t *testing.T) {
	res := &nmap.Run{
		Hosts: []nmap.Host{
			{
				Status:    nmap.Status{State: "up"},
				Addresses: []nmap.Address{{Addr: "2001:db8::1"}},
				Ports:     []nmap.Port{{ID: 443, State: nmap.State{State: "open"}}},
			},
		},
	}
	task := ScanTask{Target: "2001:db8::/64", PortRange: "443", Protocol: "tcp"}

	got, up, down := processNmapResults(res, task, silentLogger())
	if up != 1 || down != 0 {
		t.Fatalf("unexpected host counts up=%d down=%d", up, down)
	}

	// net.JoinHostPort para IPv6 adiciona colchetes.
	if _, ok := got["[2001:db8::1]:443/tcp"]; !ok {
		t.Fatalf("expected key [2001:db8::1]:443/tcp, got %v", got)
	}
}

func TestProcessNmapResults_NoPortsNoAddrs_Safe(t *testing.T) {
	res := &nmap.Run{Hosts: []nmap.Host{{Status: nmap.Status{State: "up"}}}}
	task := ScanTask{Target: "x", PortRange: "y", Protocol: "udp"}

	got, up, down := processNmapResults(res, task, silentLogger())
	if up != 1 || down != 0 {
		t.Fatalf("unexpected host counts")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty results, got %v", got)
	}
}

// --- createTargetKey / categorizeError ---

func TestCreateTargetKey_LowercasesProto(t *testing.T) {
	k := createTargetKey("10.0.0.0/24", "80", "UDP")
	if k != "10.0.0.0/24_80_udp" {
		t.Fatalf("unexpected key: %s", k)
	}
}

func TestCategorizeError(t *testing.T) {
	if got := categorizeError(nil); got != "other" {
		t.Fatalf("nil -> other, got %q", got)
	}
	if got := categorizeError(errf("SOMETHING timeout occurred")); got != "timeout" {
		t.Fatalf("timeout string -> timeout, got %q", got)
	}
	if got := categorizeError(errf("Permission denied by OS")); got != "permission" {
		t.Fatalf("permission string -> permission, got %q", got)
	}
	if got := categorizeError(errf("random")); got != "other" {
		t.Fatalf("random -> other, got %q", got)
	}
}

type errf string
func (e errf) Error() string { return string(e) }

// --- createNmapScanner sanity (does not run nmap) ---

func TestCreateNmapScanner_TCPAndUDP_DoNotError(t *testing.T) {
	ctx := context.Background()
	cfg := &cfgpkg.Config{}
	// Default: UseSYNScanEnabled() == true (via LoadConfig), but here cfg has nil UseSYNScan.
	// createNmapScanner should still succeed building options.

	// TCP
	s1, err := createNmapScanner(ScanTask{
		Target: "192.0.2.5", PortRange: "80", Protocol: "tcp",
	}, cfg, ctx)
	if err != nil || s1 == nil {
		t.Fatalf("tcp scanner build failed: %v", err)
	}

	// UDP
	s2, err := createNmapScanner(ScanTask{
		Target: "192.0.2.5", PortRange: "53", Protocol: "udp",
	}, cfg, ctx)
	if err != nil || s2 == nil {
		t.Fatalf("udp scanner build failed: %v", err)
	}
}

// --- RunImmediateScan edges without invoking real nmap ---

func TestRunImmediateScan_InvalidTarget_Err(t *testing.T) {
	ctx := context.Background()
	cfg := &cfgpkg.Config{Scanning: cfgpkg.ScanningConfig{MaxCIDRSize: 24}}
	_, _, _, _, err := RunImmediateScan(ctx, cfg, "invalid-target", "80", "tcp", 24, silentLogger())
	if err == nil {
		t.Fatalf("expected error for invalid target")
	}
}

func TestRunImmediateScan_CanceledBeforeLoop_ReturnsCtxErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &cfgpkg.Config{Scanning: cfgpkg.ScanningConfig{MaxCIDRSize: 24}}
	_, _, _, _, err := RunImmediateScan(ctx, cfg, "192.0.2.0/24", "80", "tcp", 24, silentLogger())
	if err == nil {
		t.Fatalf("expected context error")
	}
}

// --- tiny utils ---

func endsWith(s, suf string) bool {
	if len(s) < len(suf) {
		return false
	}
	return s[len(s)-len(suf):] == suf
}

// --- (informational) time-bounded sanity for context timeouts ---

func TestEnqueueScanTask_DoesNotDeadlockOnBufferedQueue(t *testing.T) {
	// This test documents the enqueue behavior: it performs a blocking send.
	// We ensure the buffer is large enough to prevent deadlocks in unit tests.
	ctx := context.Background()
	ch := make(chan ScanTask, 16)
	if err := EnqueueScanTask(ctx, ch, "10.0.0.0/24", "22", "tcp", 26); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	select {
	case <-time.After(50 * time.Millisecond):
		// ok: the function returned without blocking.
	default:
	}
}
