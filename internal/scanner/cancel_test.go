package scanner

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ullaakut/nmap/v3"

	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	metricspkg "github.com/renatogalera/openport-exporter/internal/metrics"
	taskspkg "github.com/renatogalera/openport-exporter/internal/tasks"
)

// Validate that cancel() on a running task marks it as cancelled and does not flip to failed.
func TestWorker_CancelRunningTask(t *testing.T) {
	// Stub run to block until context is cancelled
	old := runNmapFn
	var started int32
	runNmapFn = func(ctx context.Context, _ *nmap.Scanner, _ ScanTask, _ *slog.Logger) (*nmap.Run, *[]string, error) {
		atomic.StoreInt32(&started, 1)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	defer func() { runNmapFn = old }()

	cfg := &cfgpkg.Config{
		Scanning: cfgpkg.ScanningConfig{Timeout: 60, PortRange: "22", MaxCIDRSize: 32},
		Targets: []cfgpkg.TargetDef{
			{Name: "t", Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Interval: "1h"},
		},
	}
	mgr := cfgpkg.NewManager(cfg, "")
	mc := metricspkg.NewMetricsCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan ScanTask, 1)
	tm := taskspkg.NewManager(1 * time.Minute)
	StartWorkers(ctx, 1, ch, mgr, mc, slog.Default(), tm, nil)

	// Create task with one subtask
	rec, _ := tm.Create(1, "")
	ch <- ScanTask{Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", TaskID: rec.ID}

	// Wait worker to start
	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&started) == 0 {
		t.Fatalf("worker did not start")
	}

	// Cancel
	if !tm.Cancel(rec.ID) {
		t.Fatalf("cancel failed")
	}
	// Give some time for worker to observe cancel
	time.Sleep(50 * time.Millisecond)
	r := tm.Get(rec.ID)
	if r == nil || r.State != taskspkg.StateCancelled {
		t.Fatalf("expected cancelled state, got %+v", r)
	}
}
