package scanner

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Ullaakut/nmap/v3"

	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	metricspkg "github.com/renatogalera/openport-exporter/internal/metrics"
)

// Test that StartWorkers enforces scheduler.module_limits via ModuleLimiter in the worker flow.
func TestWorkers_ModuleLimitEnforced(t *testing.T) {
	// Requires creating an nmap.Scanner even though run is stubbed; skip if missing.
	skipIfNoNmap(t)

	// Stub run to simulate work and track concurrency
	var mu sync.Mutex
	var inCS, maxCS int
	oldRun := runNmapFn
	runNmapFn = func(ctx context.Context, _ *nmap.Scanner, _ ScanTask, _ *slog.Logger) (*nmap.Run, *[]string, error) {
		mu.Lock()
		inCS++
		if inCS > maxCS {
			maxCS = inCS
		}
		mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		inCS--
		mu.Unlock()
		return &nmap.Run{}, nil, nil
	}
	defer func() { runNmapFn = oldRun }()

	cfg := &cfgpkg.Config{
		Scanning:  cfgpkg.ScanningConfig{Timeout: 1, PortRange: "22", MaxCIDRSize: 32},
		Scheduler: &cfgpkg.SchedulerConfig{WorkerCount: 2, ModuleLimits: map[string]int{"modA": 1}},
		Targets: []cfgpkg.TargetDef{
			{Name: "t1", Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Interval: "1h"},
		},
	}
	mgr := cfgpkg.NewManager(cfg, "")
	mc := metricspkg.NewMetricsCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	taskCh := make(chan ScanTask, 2)

	// Start workers (2 workers, module limit for modA=1)
	StartWorkers(ctx, 2, taskCh, mgr, mc, slog.Default(), nil, nil)

	// Enqueue two tasks same module
	taskCh <- ScanTask{Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Module: "modA"}
	taskCh <- ScanTask{Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Module: "modA"}

	// wait for them to be processed
	time.Sleep(120 * time.Millisecond)
	cancel()
	close(taskCh)

	if maxCS > 1 {
		t.Fatalf("module limit violated: max concurrency=%d", maxCS)
	}
}
