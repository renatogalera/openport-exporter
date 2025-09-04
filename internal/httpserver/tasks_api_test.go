package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/renatogalera/openport-exporter/internal/collectors"
	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	openmetrics "github.com/renatogalera/openport-exporter/internal/metrics"
	prioq "github.com/renatogalera/openport-exporter/internal/priority"
	"github.com/renatogalera/openport-exporter/internal/scanner"
	"github.com/renatogalera/openport-exporter/internal/sloglogger"
	taskspkg "github.com/renatogalera/openport-exporter/internal/tasks"
)

func TestTasksAPI_CreateAndGetPending(t *testing.T) {
	mc := openmetrics.NewMetricsCollector()
	logger, _ := sloglogger.NewLogger("error", "text")
	exporter := collectors.NewExporter(mc, logger)

	// Minimal config with permissive policy
	cfg := &cfgpkg.Config{
		Server: cfgpkg.ServerConfig{Port: 0},
		Scanning: cfgpkg.ScanningConfig{
			Interval:    3600,
			Timeout:     5,
			PortRange:   "22",
			MaxCIDRSize: 24,
			UseSYNScan:  boolPtr(true),
		},
		Targets: []cfgpkg.TargetDef{
			{Name: "t1", Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Interval: "1h"},
		},
		Policy: &cfgpkg.PolicyConfig{
			ClientAllowCIDRs: []string{"127.0.0.0/8"},
			RateLimitRPS:     1000,
			RateBurst:        1000,
			MaxConcurrent:    5,
			SeriesLimit:      100000,
		},
		Scheduler: &cfgpkg.SchedulerConfig{
			WorkerCount:        1,
			TaskQueueSize:      10,
			DefaultTimeout:     "30m",
			DefaultMaxCIDRSize: 24,
			DedupeTTL:          "1m",
		},
	}
	mgr := cfgpkg.NewManager(cfg, "")

	workerQueue := make(chan scanner.ScanTask, 32)
	prio := prioq.NewQueue(workerQueue)
	prio.Start()
	tm := taskspkg.NewManager(1 * time.Minute)

	srv := NewServer(
		exporter,
		&collectors.Settings{ListenPort: "0", MetricsPath: "/metrics"},
		mgr,
		tm,
		workerQueue,
		mc,
		prio,
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Create task
	body := map[string]any{"targets": []string{"127.0.0.1/32"}, "ports": "22", "protocol": "tcp"}
	b, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/v1/tasks/scan", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	id, _ := out["task_id"].(string)
	if id == "" {
		t.Fatalf("missing task_id in response")
	}

	// Fetch status (no workers => pending)
	resp2, err := http.Get(baseURL + "/v1/tasks/" + id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
}

func boolPtr(b bool) *bool { return &b }

func TestTasksAPI_DedupeReturnsSameTask(t *testing.T) {
	mc := openmetrics.NewMetricsCollector()
	logger, _ := sloglogger.NewLogger("error", "text")
	exporter := collectors.NewExporter(mc, logger)
	cfg := &cfgpkg.Config{
		Server: cfgpkg.ServerConfig{Port: 0},
		Scanning: cfgpkg.ScanningConfig{
			Interval:    3600,
			Timeout:     5,
			PortRange:   "22",
			MaxCIDRSize: 32,
			UseSYNScan:  boolPtr(true),
		},
		Targets: []cfgpkg.TargetDef{
			{Name: "t1", Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Interval: "1h"},
		},
		Policy: &cfgpkg.PolicyConfig{
			ClientAllowCIDRs: []string{"127.0.0.0/8"},
			RateLimitRPS:     1000,
			RateBurst:        1000,
			SeriesLimit:      100000,
		},
		Scheduler: &cfgpkg.SchedulerConfig{
			WorkerCount:        1,
			TaskQueueSize:      10,
			DefaultTimeout:     "30m",
			DefaultMaxCIDRSize: 32,
			DedupeTTL:          "5m",
		},
	}
	mgr := cfgpkg.NewManager(cfg, "")
	workerQueue := make(chan scanner.ScanTask, 32)
	prio := prioq.NewQueue(workerQueue)
	tm := taskspkg.NewManager(5 * time.Minute)
	srv := NewServer(
		exporter,
		&collectors.Settings{ListenPort: "0", MetricsPath: "/metrics"},
		mgr,
		tm,
		workerQueue,
		mc,
		prio,
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	payload := map[string]any{
		"targets":    []string{"127.0.0.1/32"},
		"ports":      "22",
		"protocol":   "tcp",
		"dedupe_key": "k",
	}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(baseURL+"/v1/tasks/scan", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	var out1 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out1)
	_ = resp.Body.Close()
	id1, _ := out1["task_id"].(string)
	acc1, _ := out1["accepted"].(bool)
	if id1 == "" || !acc1 {
		t.Fatalf("expected a new task accepted, got %v", out1)
	}

	// second request with same dedupe key should not be accepted and must return the same task_id
	resp2, err := http.Post(baseURL+"/v1/tasks/scan", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post2: %v", err)
	}
	var out2 map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&out2)
	_ = resp2.Body.Close()
	id2, _ := out2["task_id"].(string)
	acc2, _ := out2["accepted"].(bool)
	if id2 != id1 || acc2 {
		t.Fatalf("expected dedupe with same id and accepted=false, got %v", out2)
	}
}

func TestTasksAPI_Cancel(t *testing.T) {
	mc := openmetrics.NewMetricsCollector()
	logger, _ := sloglogger.NewLogger("error", "text")
	exporter := collectors.NewExporter(mc, logger)
	cfg := &cfgpkg.Config{
		Server: cfgpkg.ServerConfig{Port: 0},
		Scanning: cfgpkg.ScanningConfig{
			Interval:    3600,
			Timeout:     5,
			PortRange:   "22",
			MaxCIDRSize: 32,
			UseSYNScan:  boolPtr(true),
		},
		Targets: []cfgpkg.TargetDef{
			{Name: "t1", Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Interval: "1h"},
		},
		Policy: &cfgpkg.PolicyConfig{
			ClientAllowCIDRs: []string{"127.0.0.0/8"},
			RateLimitRPS:     1000,
			RateBurst:        1000,
			SeriesLimit:      100000,
		},
		Scheduler: &cfgpkg.SchedulerConfig{
			WorkerCount:        1,
			TaskQueueSize:      10,
			DefaultTimeout:     "30m",
			DefaultMaxCIDRSize: 32,
			DedupeTTL:          "5m",
		},
	}
	mgr := cfgpkg.NewManager(cfg, "")
	workerQueue := make(chan scanner.ScanTask, 32)
	prio := prioq.NewQueue(workerQueue)
	tm := taskspkg.NewManager(5 * time.Minute)
	srv := NewServer(
		exporter,
		&collectors.Settings{ListenPort: "0", MetricsPath: "/metrics"},
		mgr,
		tm,
		workerQueue,
		mc,
		prio,
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Create a task
	payload := map[string]any{"targets": []string{"127.0.0.1/32"}, "ports": "22", "protocol": "tcp"}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(baseURL+"/v1/tasks/scan", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	id, _ := out["task_id"].(string)
	if id == "" {
		t.Fatalf("missing task_id")
	}

	// Cancel
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/v1/tasks/"+id+"/cancel", nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on cancel, got %d", resp2.StatusCode)
	}

	// Status should be cancelled (or soon after)
	resp3, err := http.Get(baseURL + "/v1/tasks/" + id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp3.StatusCode)
	}
}

func TestTasksAPI_SeriesGuardReject(t *testing.T) {
	mc := openmetrics.NewMetricsCollector()
	logger, _ := sloglogger.NewLogger("error", "text")
	exporter := collectors.NewExporter(mc, logger)

	cfg := &cfgpkg.Config{
		Server: cfgpkg.ServerConfig{Port: 0},
		Scanning: cfgpkg.ScanningConfig{
			Interval:    3600,
			Timeout:     5,
			PortRange:   "1-4",
			MaxCIDRSize: 32,
			UseSYNScan:  boolPtr(true),
		},
		Targets: []cfgpkg.TargetDef{
			{Name: "t1", Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Interval: "1h"},
		},
		Policy: &cfgpkg.PolicyConfig{
			ClientAllowCIDRs: []string{"127.0.0.0/8"},
			RateLimitRPS:     1000,
			RateBurst:        1000,
			SeriesLimit:      20,
		},
		Scheduler: &cfgpkg.SchedulerConfig{
			WorkerCount:        1,
			TaskQueueSize:      10,
			DefaultTimeout:     "30m",
			DefaultMaxCIDRSize: 32,
			DedupeTTL:          "1m",
		},
	}
	mgr := cfgpkg.NewManager(cfg, "")
	workerQueue := make(chan scanner.ScanTask, 8)
	prio := prioq.NewQueue(workerQueue)
	// don't start prio; not needed here
	tm := taskspkg.NewManager(1 * time.Minute)
	srv := NewServer(
		exporter,
		&collectors.Settings{ListenPort: "0", MetricsPath: "/metrics"},
		mgr,
		tm,
		workerQueue,
		mc,
		prio,
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Make a request that exceeds series_limit: targets=127.0.0.0/29 (8 IPs) * ports 1-4 => 32 > 20
	body := map[string]any{"targets": []string{"127.0.0.0/29"}, "ports": "1-4", "protocol": "tcp"}
	b, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/v1/tasks/scan", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 due to series guard, got %d", resp.StatusCode)
	}
}

func TestTasksAPI_Backpressure429(t *testing.T) {
	mc := openmetrics.NewMetricsCollector()
	logger, _ := sloglogger.NewLogger("error", "text")
	exporter := collectors.NewExporter(mc, logger)
	cfg := &cfgpkg.Config{
		Server: cfgpkg.ServerConfig{Port: 0},
		Scanning: cfgpkg.ScanningConfig{
			Interval:    3600,
			Timeout:     5,
			PortRange:   "22",
			MaxCIDRSize: 32,
			UseSYNScan:  boolPtr(true),
		},
		Targets: []cfgpkg.TargetDef{
			{Name: "t1", Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp", Interval: "1h"},
		},
		Policy: &cfgpkg.PolicyConfig{
			ClientAllowCIDRs: []string{"127.0.0.0/8"},
			RateLimitRPS:     1000,
			RateBurst:        1000,
			MaxConcurrent:    5,
			SeriesLimit:      1000000,
		},
		Scheduler: &cfgpkg.SchedulerConfig{
			WorkerCount:        1,
			TaskQueueSize:      1,
			DefaultTimeout:     "30m",
			DefaultMaxCIDRSize: 32,
			DedupeTTL:          "1m",
		},
	}
	mgr := cfgpkg.NewManager(cfg, "")
	workerQueue := make(chan scanner.ScanTask, 1)
	prio := prioq.NewQueue(workerQueue)
	// Do not start prio; enqueue a pending item to consume capacity estimation
	_ = prio.Enqueue("high", scanner.ScanTask{Target: "127.0.0.1/32", PortRange: "22", Protocol: "tcp"})
	tm := taskspkg.NewManager(1 * time.Minute)
	srv := NewServer(
		exporter,
		&collectors.Settings{ListenPort: "0", MetricsPath: "/metrics"},
		mgr,
		tm,
		workerQueue,
		mc,
		prio,
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Now POST one target that fans out to 1 subtask; capacity available should be 0 -> expect 429
	body := map[string]any{"targets": []string{"127.0.0.1/32"}, "ports": "22", "protocol": "tcp"}
	b, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/v1/tasks/scan", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 due to backpressure, got %d", resp.StatusCode)
	}
}
