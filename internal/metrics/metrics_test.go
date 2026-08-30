package metrics

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestUpdateMetrics(t *testing.T) {
	mc := NewMetricsCollector()

	// targetKey format: target_portRange_proto
	target := "192.168.1.0/24"
	portRange := "80,443"
	proto := "tcp"
	targetKey := target + "_" + portRange + "_" + proto

	// First run: two open ports in aggregate
	newResults := map[string]struct{}{
		"192.168.1.10:80/tcp":  {},
		"192.168.1.20:443/tcp": {},
	}
	mc.UpdateMetrics(targetKey, newResults)
	assert.Equal(
		t,
		float64(2),
		testutil.ToFloat64(mc.scanTargetOpenPortsTotal.WithLabelValues(target, portRange, proto)),
	)

	// Second run: only one open port remains
	newResults = map[string]struct{}{
		"192.168.1.10:80/tcp": {},
	}
	mc.UpdateMetrics(targetKey, newResults)
	assert.Equal(
		t,
		float64(1),
		testutil.ToFloat64(mc.scanTargetOpenPortsTotal.WithLabelValues(target, portRange, proto)),
	)
}

func TestDetailedPortRemovedAfterConfirmedClosure(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	targetKey := "192.168.1.10_22_tcp"
	detail := DetailedPort{
		Alias:    "ssh-bastion",
		IP:       "192.168.1.10",
		Port:     "22",
		Protocol: "tcp",
	}

	mc.UpdateMetricsAndDetailedPorts(
		targetKey,
		map[string]struct{}{"192.168.1.10:22/tcp": {}},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1},
	)
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	assert.Equal(t, 1, testutil.CollectAndCount(mc.portOpen))

	mc.UpdateMetricsAndDetailedPorts(targetKey, map[string]struct{}{}, DetailedPortUpdate{Generation: 1})
	assert.Equal(t, 0, mc.DetailedSeriesCount())
	assert.Equal(t, 0, testutil.CollectAndCount(mc.portOpen))
}

func TestDetailedPortWithSeparatorInAliasCanBeDeleted(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	detail := DetailedPort{Alias: "prod|ssh", IP: "192.168.1.10", Port: "22", Protocol: "tcp"}

	mc.UpdateMetricsAndDetailedPorts(
		"target_22_tcp",
		map[string]struct{}{"192.168.1.10:22/tcp": {}},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1},
	)
	assert.Equal(t, 1, testutil.CollectAndCount(mc.portOpen))

	mc.UpdateMetricsAndDetailedPorts(
		"target_22_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Generation: 1},
	)
	assert.Equal(t, 0, mc.DetailedSeriesCount())
	assert.Equal(t, 0, testutil.CollectAndCount(mc.portOpen))
}

func TestDetailedPortRemainsWhileAnotherScanSourceReportsItOpen(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	detail := DetailedPort{
		Alias:    "shared-service",
		IP:       "",
		Port:     "443",
		Protocol: "tcp",
	}

	mc.UpdateMetricsAndDetailedPorts(
		"target-a_443_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1},
	)
	mc.UpdateMetricsAndDetailedPorts(
		"target-b_443_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1},
	)

	mc.UpdateMetricsAndDetailedPorts(
		"target-a_443_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Generation: 1},
	)
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	assert.Equal(t, 1, testutil.CollectAndCount(mc.portOpen))

	mc.UpdateMetricsAndDetailedPorts(
		"target-b_443_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Generation: 1},
	)
	assert.Equal(t, 0, mc.DetailedSeriesCount())
	assert.Equal(t, 0, testutil.CollectAndCount(mc.portOpen))
}

func TestDetailedPortBudgetKeepsExistingSeriesRefreshable(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 1, false)
	details := []DetailedPort{
		{Alias: "service-a", IP: "192.168.1.10", Port: "80", Protocol: "tcp"},
		{Alias: "service-b", IP: "192.168.1.11", Port: "80", Protocol: "tcp"},
	}

	dropped := mc.UpdateMetricsAndDetailedPorts(
		"target_80_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: details, Generation: 1},
	)
	assert.Equal(t, 1, dropped)
	assert.Equal(t, 1, mc.DetailedSeriesCount())

	dropped = mc.UpdateMetricsAndDetailedPorts(
		"target_80_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: details, Generation: 1},
	)
	assert.Equal(t, 1, dropped)
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	assertDetailedStateConsistent(t, mc)
}

func TestDetailedPortBudgetCountsOnlyCurrentScanDrops(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 1, false)
	details := []DetailedPort{
		{Alias: "service-a", IP: "192.168.1.10", Port: "80", Protocol: "tcp"},
		{Alias: "service-b", IP: "192.168.1.11", Port: "80", Protocol: "tcp"},
	}

	dropped := mc.UpdateMetricsAndDetailedPorts(
		"target-a_80_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: details, Generation: 1},
	)
	assert.Equal(t, 1, dropped)
	assert.Equal(t, float64(1), testutil.ToFloat64(mc.detailsSeriesDropped))

	dropped = mc.UpdateMetricsAndDetailedPorts(
		"unrelated_443_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Generation: 1},
	)
	assert.Equal(t, 0, dropped)
	assert.Equal(t, float64(1), testutil.ToFloat64(mc.detailsSeriesDropped))
	unrelated := mc.detailedPortSources[sourceForTargetKey("unrelated_443_tcp")]
	assert.NotNil(t, unrelated)
	assert.Empty(t, unrelated.Ports)
}

func TestDetailedPortClosurePromotesCurrentOmittedSeries(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 1, false)
	first := DetailedPort{Alias: "service-a", IP: "192.168.1.10", Port: "80", Protocol: "tcp"}
	second := DetailedPort{Alias: "service-b", IP: "192.168.1.11", Port: "80", Protocol: "tcp"}

	initialDropped := mc.UpdateMetricsAndDetailedPorts(
		"target_80_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: []DetailedPort{first, second}, Generation: 1},
	)
	assert.Equal(t, 1, initialDropped)
	assert.Contains(t, mc.detailedPorts, first)
	assert.NotContains(t, mc.detailedPorts, second)

	dropped := mc.UpdateMetricsAndDetailedPorts(
		"target_80_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: []DetailedPort{second}, Generation: 1},
	)

	assert.Equal(t, 0, dropped)
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	assert.Contains(t, mc.detailedPorts, second)
	assert.NotContains(t, mc.detailedPorts, first)
}

func TestDetailedPortBudgetShrinkAndGrow(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 3, false)
	details := []DetailedPort{
		{Alias: "service-a", IP: "192.168.1.10", Port: "80", Protocol: "tcp"},
		{Alias: "service-b", IP: "192.168.1.11", Port: "80", Protocol: "tcp"},
		{Alias: "service-c", IP: "192.168.1.12", Port: "80", Protocol: "tcp"},
	}
	mc.UpdateMetricsAndDetailedPorts(
		"target_80_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: details, Generation: 1},
	)

	mc.ConfigureDetailedMetrics(2, true, 1, false)
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	assert.Equal(t, 1, testutil.CollectAndCount(mc.portOpen))
	assert.Equal(t, float64(2), testutil.ToFloat64(mc.detailsSeriesDropped))

	mc.ConfigureDetailedMetrics(3, true, 3, false)
	mc.UpdateMetricsAndDetailedPorts(
		"target_80_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: details, Generation: 3},
	)
	assert.Equal(t, 3, mc.DetailedSeriesCount())
	assert.Equal(t, 3, testutil.CollectAndCount(mc.portOpen))
}

func TestDetailedPortSourceTTLUsesScheduledMinimum(t *testing.T) {
	mc := NewMetricsCollector()
	base := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	mc.now = func() time.Time { return base }
	mc.SetSweeperTTL(30 * time.Minute)
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	sourceID := DetailedSource{Target: "target", PortRange: "22", Protocol: "tcp"}
	mc.ConfigureDetailedSourceTTLs(1, []DetailedSourceTTLRule{{
		Source: sourceID,
		MinTTL: 3 * time.Hour,
	}})
	detail := DetailedPort{Alias: "ssh", IP: "192.168.1.10", Port: "22", Protocol: "tcp"}
	mc.UpdateMetricsAndDetailedPorts(
		"target_22_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{
			Ports:      []DetailedPort{detail},
			Generation: 1,
			Source:     sourceID,
		},
	)

	mc.sweepOnce(base.Add(2 * time.Hour))
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	mc.sweepOnce(base.Add(3 * time.Hour))
	assert.Equal(t, 0, mc.DetailedSeriesCount())
	assert.Equal(t, 0, testutil.CollectAndCount(mc.portOpen))
}

func TestDetailedSourceTTLRulesUpdateExistingShardAndCannotBeDowngraded(t *testing.T) {
	mc := NewMetricsCollector()
	base := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	now := base
	mc.now = func() time.Time { return now }
	mc.SetSweeperTTL(30 * time.Minute)
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	parent := DetailedSource{Target: "192.168.1.0/24", PortRange: "22", Protocol: "tcp"}
	shard := DetailedSource{Target: "192.168.1.64/26", PortRange: "22", Protocol: "TCP"}
	mc.ConfigureDetailedSourceTTLs(1, []DetailedSourceTTLRule{{Source: parent, MinTTL: 3 * time.Hour}})
	detail := DetailedPort{Alias: "ssh", IP: "192.168.1.70", Port: "22", Protocol: "tcp"}
	mc.UpdateMetricsAndDetailedPorts(
		"192.168.1.64/26_22_tcp",
		map[string]struct{}{"192.168.1.70:22/tcp": {}},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1, Source: shard},
	)
	normalizedShard := normalizeDetailedSource(shard)
	assert.Equal(t, 3*time.Hour, mc.detailedPortSources[normalizedShard].MinTTL)

	// A live interval increase must update existing ownership before the next
	// successful scan. A scan from an API task with the same tuple then inherits
	// that configured policy instead of replacing it with the fallback TTL.
	mc.ConfigureDetailedSourceTTLs(1, []DetailedSourceTTLRule{{Source: parent, MinTTL: 72 * time.Hour}})
	assert.Equal(t, 72*time.Hour, mc.detailedPortSources[normalizedShard].MinTTL)
	now = base.Add(time.Hour)
	mc.UpdateMetricsAndDetailedPorts(
		"192.168.1.64/26_22_tcp",
		map[string]struct{}{"192.168.1.70:22/tcp": {}},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1, Source: shard},
	)
	assert.Equal(t, 72*time.Hour, mc.detailedPortSources[normalizedShard].MinTTL)

	mc.sweepOnce(now.Add(3 * time.Hour))
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	mc.sweepOnce(now.Add(72 * time.Hour))
	assert.Equal(t, 0, mc.DetailedSeriesCount())
}

func TestDetailedPortSuccessfulReconfirmationRenewsTTL(t *testing.T) {
	mc := NewMetricsCollector()
	base := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	now := base
	mc.now = func() time.Time { return now }
	mc.SetSweeperTTL(time.Hour)
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	detail := DetailedPort{Alias: "ssh", IP: "192.168.1.10", Port: "22", Protocol: "tcp"}
	update := DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1}
	mc.UpdateMetricsAndDetailedPorts("target_22_tcp", map[string]struct{}{}, update)
	now = base.Add(45 * time.Minute)
	mc.UpdateMetricsAndDetailedPorts("target_22_tcp", map[string]struct{}{}, update)

	mc.sweepOnce(base.Add(time.Hour))
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	mc.sweepOnce(base.Add(105 * time.Minute))
	assert.Equal(t, 0, mc.DetailedSeriesCount())
}

func TestConfigureScanLifecycleAppliesGlobalTTLIncreaseBeforeSweep(t *testing.T) {
	mc := NewMetricsCollector()
	base := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	mc.now = func() time.Time { return base }
	mc.ConfigureScanLifecycle(1, true, 10, false, nil, nil, 30*time.Minute)
	detail := DetailedPort{Alias: "api", IP: "192.168.1.10", Port: "22", Protocol: "tcp"}
	mc.UpdateMetricsAndDetailedPorts(
		"192.168.1.10_22_tcp",
		map[string]struct{}{"192.168.1.10:22/tcp": {}},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1},
	)

	mc.ConfigureScanLifecycle(1, true, 10, false, nil, nil, 3*time.Hour)
	mc.sweepOnce(base.Add(time.Hour))
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	mc.sweepOnce(base.Add(3 * time.Hour))
	assert.Equal(t, 0, mc.DetailedSeriesCount())
}

func TestOlderConcurrentScanCannotRestoreClosedDetailedState(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	detail := DetailedPort{Alias: "ssh", IP: "192.168.1.10", Port: "22", Protocol: "tcp"}
	initial := mc.NextScanSequence()
	older := mc.NextScanSequence()
	newer := mc.NextScanSequence()
	targetKey := "192.168.1.10_22_tcp"

	mc.UpdateMetricsAndDetailedPorts(
		targetKey,
		map[string]struct{}{"192.168.1.10:22/tcp": {}},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1, ScanSequence: initial},
	)
	mc.UpdateMetricsAndDetailedPorts(
		targetKey,
		map[string]struct{}{},
		DetailedPortUpdate{Generation: 1, ScanSequence: newer},
	)
	mc.UpdateMetricsAndDetailedPorts(
		targetKey,
		map[string]struct{}{"192.168.1.10:22/tcp": {}},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1, ScanSequence: older},
	)

	assert.Equal(t, 0, mc.DetailedSeriesCount())
	assert.Equal(t, float64(0), testutil.ToFloat64(
		mc.scanTargetOpenPortsTotal.WithLabelValues("192.168.1.10", "22", "tcp"),
	))
	assert.Equal(t, float64(1), testutil.ToFloat64(
		mc.portStateChanges.WithLabelValues("192.168.1.10", "22", "tcp", "closed_to_open"),
	))
	assert.Equal(t, float64(1), testutil.ToFloat64(
		mc.portStateChanges.WithLabelValues("192.168.1.10", "22", "tcp", "open_to_closed"),
	))
}

func TestOlderAcceptedScanCannotOverwriteNewerLastResultGauges(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	older := mc.NextScanSequence()
	newer := mc.NextScanSequence()
	targetKey := "192.168.1.10_22_tcp"
	assert.True(t, mc.UpdateMetricsForScanGeneration(
		targetKey,
		map[string]struct{}{"192.168.1.10:22/tcp": {}},
		older,
		1,
	))
	assert.True(t, mc.UpdateMetricsForScanGeneration(targetKey, map[string]struct{}{}, newer, 1))
	newerCompletion := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	assert.True(t, mc.UpdateLastResultMetricsForScan(
		targetKey, newer, 1, newerCompletion, 2.5, true, 2, 3,
	))
	assert.False(t, mc.UpdateLastResultMetricsForScan(
		targetKey, older, 1, newerCompletion.Add(time.Hour), 9.5, true, 9, 9,
	))

	assert.Equal(t, float64(newerCompletion.Unix()), testutil.ToFloat64(
		mc.lastScanTimestamp.WithLabelValues("192.168.1.10", "22", "tcp"),
	))
	assert.Equal(t, 2.5, testutil.ToFloat64(
		mc.scanDuration.WithLabelValues("192.168.1.10", "22", "tcp"),
	))
	assert.Equal(t, float64(2), testutil.ToFloat64(
		mc.hostUpCount.WithLabelValues("192.168.1.10", "22", "tcp"),
	))
	assert.Equal(t, float64(3), testutil.ToFloat64(
		mc.hostDownCount.WithLabelValues("192.168.1.10", "22", "tcp"),
	))
}

func TestOrderingTombstoneOutlivesTTLWhileOlderScanIsInFlight(t *testing.T) {
	mc := NewMetricsCollector()
	base := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	mc.now = func() time.Time { return base }
	mc.SetSweeperTTL(30 * time.Minute)
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	source := DetailedSource{Target: "192.168.1.10", PortRange: "22", Protocol: "tcp"}
	older := mc.BeginScan(source)
	newer := mc.BeginScan(source)
	targetKey := "192.168.1.10_22_tcp"
	mc.UpdateMetricsAndDetailedPorts(
		targetKey,
		map[string]struct{}{},
		DetailedPortUpdate{Generation: 1, ScanSequence: newer, Source: source},
	)
	mc.EndScan(source, newer)

	mc.sweepOnce(base.Add(time.Hour))
	assert.Contains(t, mc.detailedPortSources, normalizeDetailedSource(source))
	_, aggregatePresent := mc.scannedTargets.Load(targetKey)
	assert.True(t, aggregatePresent)

	detail := DetailedPort{Alias: "ssh", IP: "192.168.1.10", Port: "22", Protocol: "tcp"}
	mc.UpdateMetricsAndDetailedPorts(
		targetKey,
		map[string]struct{}{"192.168.1.10:22/tcp": {}},
		DetailedPortUpdate{
			Ports: []DetailedPort{detail}, Generation: 1, ScanSequence: older, Source: source,
		},
	)
	mc.EndScan(source, older)
	assert.Equal(t, 0, mc.DetailedSeriesCount())

	mc.sweepOnce(base.Add(time.Hour))
	assert.NotContains(t, mc.detailedPortSources, normalizeDetailedSource(source))
}

func TestDetailedPortExpiredOwnerKeepsFreshSharedOwner(t *testing.T) {
	mc := NewMetricsCollector()
	base := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	now := base
	mc.now = func() time.Time { return now }
	mc.SetSweeperTTL(time.Hour)
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	detail := DetailedPort{Alias: "shared", Port: "443", Protocol: "tcp"}

	mc.UpdateMetricsAndDetailedPorts(
		"target-a_443_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1},
	)
	now = base.Add(30 * time.Minute)
	mc.UpdateMetricsAndDetailedPorts(
		"target-b_443_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1},
	)

	mc.sweepOnce(base.Add(time.Hour))
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	assert.NotContains(t, mc.detailedPortSources, sourceForTargetKey("target-a_443_tcp"))
	assert.Contains(t, mc.detailedPortSources, sourceForTargetKey("target-b_443_tcp"))

	mc.sweepOnce(base.Add(90 * time.Minute))
	assert.Equal(t, 0, mc.DetailedSeriesCount())
}

func TestDetailedPortOldGenerationCannotRecreateSeries(t *testing.T) {
	mc := NewMetricsCollector()
	mc.ConfigureDetailedMetrics(1, true, 10, false)
	detail := DetailedPort{Alias: "old-alias", IP: "192.168.1.10", Port: "22", Protocol: "tcp"}
	mc.UpdateMetricsAndDetailedPorts(
		"target_22_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1},
	)
	assert.Equal(t, 1, mc.DetailedSeriesCount())

	mc.ConfigureDetailedMetrics(2, true, 10, true)
	assert.Equal(t, 0, mc.DetailedSeriesCount())
	// A delayed reload callback must not regress the active generation.
	mc.ConfigureDetailedMetrics(1, true, 10, true)

	mc.UpdateMetricsAndDetailedPorts(
		"target_22_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: []DetailedPort{detail}, Generation: 1},
	)
	assert.Equal(t, 0, mc.DetailedSeriesCount())
	assert.Equal(t, 0, testutil.CollectAndCount(mc.portOpen))

	newDetail := DetailedPort{Alias: "new-alias", IP: detail.IP, Port: detail.Port, Protocol: detail.Protocol}
	mc.UpdateMetricsAndDetailedPorts(
		"target_22_tcp",
		map[string]struct{}{},
		DetailedPortUpdate{Ports: []DetailedPort{newDetail}, Generation: 2},
	)
	assert.Equal(t, 1, mc.DetailedSeriesCount())
	assert.Contains(t, mc.detailedPorts, newDetail)
}

func TestDetailedPortConcurrentReconcileAndSweep(t *testing.T) {
	mc := NewMetricsCollector()
	base := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	mc.now = func() time.Time { return base }
	mc.SetSweeperTTL(time.Hour)
	mc.ConfigureDetailedMetrics(1, true, 8, false)

	var wait sync.WaitGroup
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			port := DetailedPort{
				Alias:    "shared",
				IP:       "",
				Port:     fmt.Sprintf("%d", 1000+index),
				Protocol: "TCP",
			}
			mc.UpdateMetricsAndDetailedPorts(
				fmt.Sprintf("target-%d_ports_tcp", index),
				map[string]struct{}{},
				DetailedPortUpdate{Ports: []DetailedPort{port}, Generation: 1},
			)
		}(i)
	}
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			mc.sweepOnce(base.Add(30 * time.Minute))
		}()
	}
	wait.Wait()

	assert.LessOrEqual(t, mc.DetailedSeriesCount(), 8)
	assertDetailedStateConsistent(t, mc)
}

func assertDetailedStateConsistent(t *testing.T, mc *Collector) {
	t.Helper()
	mc.detailedPortsMu.Lock()
	exposed := len(mc.detailedPorts)
	if mc.detailedSeriesBudget > 0 && exposed > mc.detailedSeriesBudget {
		mc.detailedPortsMu.Unlock()
		t.Fatalf("detail budget exceeded: budget=%d exposed=%d", mc.detailedSeriesBudget, exposed)
	}
	for port, series := range mc.detailedPorts {
		if len(series.Owners) == 0 {
			mc.detailedPortsMu.Unlock()
			t.Fatalf("series %+v has no owners", port)
		}
		for owner := range series.Owners {
			source := mc.detailedPortSources[owner]
			if source == nil {
				mc.detailedPortsMu.Unlock()
				t.Fatalf("series %+v references missing owner %+v", port, owner)
			}
			if _, exists := source.Ports[port]; !exists {
				mc.detailedPortsMu.Unlock()
				t.Fatalf("series %+v missing from owner %+v", port, owner)
			}
		}
	}
	for sourceKey, source := range mc.detailedPortSources {
		for port := range source.Ports {
			series := mc.detailedPorts[port]
			if series == nil {
				mc.detailedPortsMu.Unlock()
				t.Fatalf("source %+v references missing series %+v", sourceKey, port)
			}
			if _, exists := series.Owners[sourceKey]; !exists {
				mc.detailedPortsMu.Unlock()
				t.Fatalf("source %+v is not an owner of %+v", sourceKey, port)
			}
		}
	}
	mc.detailedPortsMu.Unlock()

	if got := testutil.CollectAndCount(mc.portOpen); got != exposed {
		t.Fatalf("GaugeVec/map mismatch: gauge=%d map=%d", got, exposed)
	}
}

func sourceForTargetKey(targetKey string) DetailedSource {
	target, portRange, protocol := parseTargetKey(targetKey)
	return normalizeDetailedSource(DetailedSource{
		Target:    target,
		PortRange: portRange,
		Protocol:  protocol,
	})
}

func TestCanScan(t *testing.T) {
	mc := NewMetricsCollector()
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	mc.now = func() time.Time { return now }
	targetKey := "192.168.1.1_80"
	scanInterval := 10 * time.Second

	// Register a new scan
	mc.RegisterScan(targetKey)

	// Check that a new scan cannot be performed immediately
	canScan := mc.CanScan(targetKey, scanInterval)
	assert.False(t, canScan, "A new scan should not be allowed right after registering a scan")

	now = now.Add(11 * time.Second)

	// Check that a new scan can be performed after enough time
	canScan = mc.CanScan(targetKey, scanInterval)
	assert.True(t, canScan, "A new scan should be allowed after the scan interval")
}

func TestCanScanImmediatelyForNewDetailGeneration(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RegisterScanForGeneration("192.168.1.0/24_22_tcp", 1)
	assert.False(t, mc.CanScanForGeneration("192.168.1.0/24_22_tcp", time.Hour, 1))
	assert.True(t, mc.CanScanForGeneration("192.168.1.0/24_22_tcp", time.Hour, 2))
}

func TestScheduledIntervalReloadRetainsEnqueueGuard(t *testing.T) {
	mc := NewMetricsCollector()
	base := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	mc.now = func() time.Time { return base }
	mc.SetSweeperTTL(30 * time.Minute)
	key := "192.168.1.0/24_22_tcp"
	mc.RegisterScanForGeneration(key, 1)
	mc.ConfigureScheduledTargetTTLs(map[string]time.Duration{key: 72 * time.Hour})

	mc.sweepOnce(base.Add(3 * time.Hour))
	assert.False(t, mc.CanScanForGeneration(key, 24*time.Hour, 1))
	mc.sweepOnce(base.Add(72 * time.Hour))
	assert.True(t, mc.CanScanForGeneration(key, 24*time.Hour, 1))
}

func TestScheduledTTLRuleRetainsAggregateShardBetweenScans(t *testing.T) {
	mc := NewMetricsCollector()
	base := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	mc.now = func() time.Time { return base }
	mc.SetSweeperTTL(30 * time.Minute)
	mc.ConfigureDetailedMetricsWithSourceTTLs(
		1,
		true,
		10,
		false,
		[]DetailedSourceTTLRule{{
			Source: DetailedSource{Target: "192.168.1.0/24", PortRange: "22", Protocol: "tcp"},
			MinTTL: 3 * time.Hour,
		}},
	)
	key := "192.168.1.64/26_22_tcp"
	mc.UpdateMetrics(key, map[string]struct{}{"192.168.1.70:22/tcp": {}})

	mc.sweepOnce(base.Add(time.Hour))
	_, exists := mc.scannedTargets.Load(key)
	assert.True(t, exists)
	mc.sweepOnce(base.Add(3 * time.Hour))
	_, exists = mc.scannedTargets.Load(key)
	assert.False(t, exists)
}

func TestRegisterScan(t *testing.T) {
	mc := NewMetricsCollector()
	targetKey := "192.168.1.1_80_tcp"
	openPorts := map[string]struct{}{"192.168.1.1:80/tcp": {}}
	mc.UpdateMetrics(targetKey, openPorts)

	mc.RegisterScan(targetKey)

	_, scheduled := mc.scheduledTargets.Load(targetKey)
	assert.True(t, scheduled, "the enqueue timestamp should be registered")
	scanInfo, exists := mc.scannedTargets.Load(targetKey)
	assert.True(t, exists, "the last successful result should be preserved")
	assert.Equal(t, openPorts, scanInfo.(*ScanInfo).Ports)
}

func TestObserveScanDuration(t *testing.T) {
	mc := NewMetricsCollector()
	target := "192.168.1.1"
	portRange := "80-443"
	protocol := "tcp"
	duration := 1.23

	// Observe the scan duration
	mc.ObserveScanDuration(target, portRange, protocol, duration)

	// Check if the scan duration metric was updated correctly
	assert.Equal(t, duration, testutil.ToFloat64(mc.scanDuration.WithLabelValues(target, portRange, protocol)))
}

func TestUpdateTaskQueueSize(t *testing.T) {
	mc := NewMetricsCollector()
	queueSize := 5

	// Update the task queue size metric
	mc.UpdateTaskQueueSize(queueSize)

	// Check if the task queue size metric was updated correctly
	assert.Equal(t, float64(queueSize), testutil.ToFloat64(mc.schedulerQueueSize))
}
