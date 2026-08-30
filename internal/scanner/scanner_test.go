package scanner

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/renatogalera/openport-exporter/internal/allowlist"
	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	metricspkg "github.com/renatogalera/openport-exporter/internal/metrics"

	"github.com/Ullaakut/nmap/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// --- helpers ---

func silentLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
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
	// ones=24, max=16 => function cannot "aggregate"; returns the original CIDR.
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
	// /126 -> /128 => 4 subnets (individual addresses)
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

func TestEnqueueScheduledScanTaskPropagatesGenerationToEverySubnet(t *testing.T) {
	ctx := context.Background()
	queue := make(chan ScanTask, 8)
	const generation = uint64(42)

	if err := EnqueueScheduledScanTask(
		ctx,
		queue,
		"192.168.10.0/24",
		"22",
		"tcp",
		26,
		generation,
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := len(queue); got != 4 {
		t.Fatalf("want 4 subnets, got %d", got)
	}
	for len(queue) > 0 {
		if task := <-queue; task.DetailGeneration != generation {
			t.Fatalf(
				"task %s detail generation: want %d, got %d",
				task.Target,
				generation,
				task.DetailGeneration,
			)
		}
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

	// net.JoinHostPort for IPv6 adds brackets.
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

func TestBuildDetailedPortsCollapsesSharedAliasWhenIPIsExcluded(t *testing.T) {
	includeIP := false
	cfg := &cfgpkg.BackgroundDetailsConfig{IncludeAlias: true, IncludeIP: &includeIP}
	cache := allowlist.Build([]allowlist.Entry{
		{Alias: "web-cluster", CIDR: "192.168.1.0/24", Protocol: "tcp", Ports: []string{"443"}},
	})
	results := map[string]struct{}{
		"192.168.1.10:443/tcp": {},
		"192.168.1.11:443/tcp": {},
	}

	details := buildDetailedPorts(results, cfg, cache)
	if len(details) != 1 {
		t.Fatalf("expected one collapsed detail series, got %d: %v", len(details), details)
	}
	if details[0].Alias != "web-cluster" || details[0].IP != "" ||
		details[0].Port != "443" || details[0].Protocol != "tcp" {
		t.Fatalf("unexpected detail labels: %+v", details[0])
	}
}

func TestScanTargetOpenThenClosedReconcilesDetailedSeriesImmediately(t *testing.T) {
	includeIP := true
	cfg := &cfgpkg.Config{
		BackgroundDetails: &cfgpkg.BackgroundDetailsConfig{
			Enabled:      true,
			SeriesBudget: 10,
			IncludeAlias: true,
			IncludeIP:    &includeIP,
		},
	}
	collector := metricspkg.NewMetricsCollector()
	collector.ConfigureDetailedMetrics(cfg.DetailsRevision(), true, 10, false)
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)
	cache := allowlist.Build([]allowlist.Entry{
		{Alias: "ssh-bastion", CIDR: "192.168.1.10/32", Protocol: "tcp", Ports: []string{"22"}},
	})
	task := ScanTask{Target: "192.168.1.10", PortRange: "22", Protocol: "tcp"}
	results := []*nmap.Run{
		nmapResultWithPortState("open"),
		nmapResultWithPortState("closed"),
	}
	installScannerTestHooks(t, func() (*nmap.Run, error) {
		result := results[0]
		results = results[1:]
		return result, nil
	})

	openCount, _, _, _, err := scanTarget(
		context.Background(),
		task,
		cfg,
		collector,
		silentLogger(),
		cache,
	)
	if err != nil || openCount != 1 {
		t.Fatalf("open scan: count=%d err=%v", openCount, err)
	}
	if collector.DetailedSeriesCount() != 1 {
		t.Fatalf("expected one detailed series after open scan")
	}
	assertGatheredMetricValue(t, registry, "openport_port_open", map[string]string{
		"alias": "ssh-bastion", "ip": "192.168.1.10", "port": "22", "protocol": "tcp",
	}, 1)

	openCount, _, _, _, err = scanTarget(
		context.Background(),
		task,
		cfg,
		collector,
		silentLogger(),
		cache,
	)
	if err != nil || openCount != 0 {
		t.Fatalf("closed scan: count=%d err=%v", openCount, err)
	}
	if collector.DetailedSeriesCount() != 0 {
		t.Fatalf("detailed series was not removed after confirmed closure")
	}
	if got, err := testutil.GatherAndCount(registry, "openport_port_open"); err != nil || got != 0 {
		t.Fatalf("expected no openport_port_open family, got %d (err=%v)", got, err)
	}

	labels := map[string]string{"target": "192.168.1.10", "port_range": "22", "protocol": "tcp"}
	assertGatheredMetricValue(t, registry, "openport_scan_target_ports_open", labels, 0)
	labels["change_type"] = "closed_to_open"
	assertGatheredMetricValue(t, registry, "openport_port_state_changes_total", labels, 1)
	labels["change_type"] = "open_to_closed"
	assertGatheredMetricValue(t, registry, "openport_port_state_changes_total", labels, 1)
}

func TestScanTargetErrorPreservesLastSuccessfulDetailedState(t *testing.T) {
	includeIP := true
	cfg := &cfgpkg.Config{
		BackgroundDetails: &cfgpkg.BackgroundDetailsConfig{
			Enabled:      true,
			SeriesBudget: 10,
			IncludeAlias: true,
			IncludeIP:    &includeIP,
		},
	}
	collector := metricspkg.NewMetricsCollector()
	collector.ConfigureDetailedMetrics(cfg.DetailsRevision(), true, 10, false)
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)
	cache := allowlist.Build([]allowlist.Entry{
		{Alias: "ssh-bastion", CIDR: "192.168.1.10/32", Protocol: "tcp", Ports: []string{"22"}},
	})
	task := ScanTask{Target: "192.168.1.10", PortRange: "22", Protocol: "tcp"}
	calls := 0
	installScannerTestHooks(t, func() (*nmap.Run, error) {
		calls++
		if calls == 1 {
			return nmapResultWithPortState("open"), nil
		}
		return nil, errors.New("timeout while scanning")
	})

	if _, _, _, _, err := scanTarget(
		context.Background(),
		task,
		cfg,
		collector,
		silentLogger(),
		cache,
	); err != nil {
		t.Fatalf("initial scan failed: %v", err)
	}
	if _, _, _, _, err := scanTarget(
		context.Background(),
		task,
		cfg,
		collector,
		silentLogger(),
		cache,
	); err == nil {
		t.Fatal("expected second scan to fail")
	}

	if collector.DetailedSeriesCount() != 1 {
		t.Fatalf("failed scan removed the last successful detailed state")
	}
	labels := map[string]string{"target": "192.168.1.10", "port_range": "22", "protocol": "tcp"}
	assertGatheredMetricValue(t, registry, "openport_scan_target_ports_open", labels, 1)
	labels["change_type"] = "closed_to_open"
	assertGatheredMetricValue(t, registry, "openport_port_state_changes_total", labels, 1)
	labels["change_type"] = "open_to_closed"
	assertGatheredMetricAbsent(t, registry, "openport_port_state_changes_total", labels)
}

func TestQueuedScheduledScanFromOldGenerationCannotRecreateDetails(t *testing.T) {
	includeIP := true
	cfg := &cfgpkg.Config{BackgroundDetails: &cfgpkg.BackgroundDetailsConfig{
		Enabled: true, SeriesBudget: 10, IncludeAlias: true, IncludeIP: &includeIP,
	}}
	collector := metricspkg.NewMetricsCollector()
	collector.ConfigureDetailedMetrics(2, true, 10, true)
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)
	cache := allowlist.Build([]allowlist.Entry{{
		Alias: "new-alias", CIDR: "192.168.1.10/32", Protocol: "tcp", Ports: []string{"22"},
	}})
	task := ScanTask{
		Target: "192.168.1.10", PortRange: "22", Protocol: "tcp", DetailGeneration: 1,
	}
	installScannerTestHooks(t, func() (*nmap.Run, error) {
		return nmapResultWithPortState("open"), nil
	})

	openCount, _, _, _, err := scanTarget(
		context.Background(), task, cfg, collector, silentLogger(), cache,
	)
	if err != nil || openCount != 1 {
		t.Fatalf("old queued scan: count=%d err=%v", openCount, err)
	}
	if collector.DetailedSeriesCount() != 0 {
		t.Fatal("old scheduled generation recreated detailed state")
	}
	if got, err := testutil.GatherAndCount(
		registry,
		"openport_scan_target_ports_open",
		"openport_last_scan_timestamp_seconds",
	); err != nil || got != 0 {
		t.Fatalf("old scheduled generation recreated aggregate state: families=%d err=%v", got, err)
	}
}

func installScannerTestHooks(t *testing.T, next func() (*nmap.Run, error)) {
	t.Helper()
	previousCreate := createNmapScannerFn
	previousRun := runNmapFn
	createNmapScannerFn = func(ScanTask, *cfgpkg.Config, context.Context) (*nmap.Scanner, error) {
		return &nmap.Scanner{}, nil
	}
	runNmapFn = func(
		context.Context,
		*nmap.Scanner,
		ScanTask,
		*slog.Logger,
	) (*nmap.Run, *[]string, error) {
		result, err := next()
		return result, nil, err
	}
	t.Cleanup(func() {
		createNmapScannerFn = previousCreate
		runNmapFn = previousRun
	})
}

func nmapResultWithPortState(state string) *nmap.Run {
	return &nmap.Run{Hosts: []nmap.Host{{
		Status:    nmap.Status{State: "up"},
		Addresses: []nmap.Address{{Addr: "192.168.1.10"}},
		Ports:     []nmap.Port{{ID: 22, State: nmap.State{State: state}}},
	}}}
}

func assertGatheredMetricValue(
	t *testing.T,
	gatherer prometheus.Gatherer,
	name string,
	labels map[string]string,
	want float64,
) {
	t.Helper()
	metric := findGatheredMetric(t, gatherer, name, labels)
	if metric == nil {
		t.Fatalf("metric %s with labels %v not found", name, labels)
	}
	var got float64
	switch {
	case metric.Gauge != nil:
		got = metric.GetGauge().GetValue()
	case metric.Counter != nil:
		got = metric.GetCounter().GetValue()
	default:
		t.Fatalf("metric %s is neither gauge nor counter", name)
	}
	if got != want {
		t.Fatalf("metric %s with labels %v: want %v, got %v", name, labels, want, got)
	}
}

func assertGatheredMetricAbsent(
	t *testing.T,
	gatherer prometheus.Gatherer,
	name string,
	labels map[string]string,
) {
	t.Helper()
	if metric := findGatheredMetric(t, gatherer, name, labels); metric != nil {
		t.Fatalf("metric %s with labels %v unexpectedly exists", name, labels)
	}
}

func findGatheredMetric(
	t *testing.T,
	gatherer prometheus.Gatherer,
	name string,
	labels map[string]string,
) *dto.Metric {
	t.Helper()
	families, err := gatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			if metricHasLabels(metric, labels) {
				return metric
			}
		}
	}
	return nil
}

func metricHasLabels(metric *dto.Metric, labels map[string]string) bool {
	if len(metric.Label) != len(labels) {
		return false
	}
	for _, pair := range metric.Label {
		if labels[pair.GetName()] != pair.GetValue() {
			return false
		}
	}
	return true
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
	// Skip if nmap is not available in PATH on the CI/host.
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("skipping: nmap binary not found in PATH")
	}
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
