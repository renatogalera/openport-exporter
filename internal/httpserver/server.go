package httpserver

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/semaphore"

	"github.com/renatogalera/openport-exporter/internal/collectors"
	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	openmetrics "github.com/renatogalera/openport-exporter/internal/metrics"
	prioq "github.com/renatogalera/openport-exporter/internal/priority"
	"github.com/renatogalera/openport-exporter/internal/scanner"
	taskspkg "github.com/renatogalera/openport-exporter/internal/tasks"
)

const rootTemplate = `<html>
 <head><title>OpenPort Exporter</title></head>
 <body>
   <h1>OpenPort Exporter</h1>
   <p>Metrics at: <a href='{{ .MetricsPath }}'>{{ .MetricsPath }}</a></p>
   <p>Source: <a href='https://github.com/renatogalera/openport-exporter'>github.com/renatogalera/openport-exporter</a></p>
   <!-- /probe endpoint intentionally not supported -->
 </body>
 </html>`

var portsRe = regexp.MustCompile(`^(?:\d{1,5}(?:-\d{1,5})?)(?:\s*,\s*(?:\d{1,5}(?:-\d{1,5})?))*$`)

// NewServer wires the custom registry and handlers. Uses ConfigManager for safe live reads.
func NewServer(
	e *collectors.Exporter,
	s *collectors.Settings,
	mgr *cfgpkg.Manager,
	tm *taskspkg.Manager,
	workerQueue chan scanner.ScanTask,
	mc *openmetrics.Collector,
	prio *prioq.Queue,
) *http.Server {
	t := template.Must(template.New("root").Parse(rootTemplate))

	reg := prometheus.NewRegistry()
	reg.MustRegister(e)
	if s.EnableBuildInfo {
		reg.MustRegister(promcollectors.NewBuildInfoCollector())
	}
	if s.EnableGoCollector {
		reg.MustRegister(promcollectors.NewGoCollector())
	}

	// API requests metrics
	apiReq := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openport",
			Name:      "api_requests_total",
			Help:      "API requests by route, method, code.",
		},
		[]string{"route", "method", "code"},
	)
	reg.MustRegister(apiReq)

	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		MaxRequestsInFlight: 8,
		Timeout:             30 * time.Second,
	})

	mux := http.NewServeMux()
	// Read initial config and build rate guards / trusted proxies
	cfg0 := mgr.Get()
	var guards *RateGuards
	if cfg0.Policy != nil && cfg0.Policy.RateLimitRPS > 0 {
		guards = NewRateGuards(cfg0.Policy.RateLimitRPS, cfg0.Policy.RateBurst, 10*time.Minute, true)
	}
	var trustedProxies []*net.IPNet
	if len(cfg0.Server.TrustedProxiesCIDRs) > 0 {
		for _, c := range cfg0.Server.TrustedProxiesCIDRs {
			if _, nw, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && nw != nil {
				trustedProxies = append(trustedProxies, nw)
			}
		}
	}

	readyCh := make(chan struct{}, 1)
	isReady := false

	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/-/ready", func(w http.ResponseWriter, _ *http.Request) {
		if !isReady {
			select {
			case <-readyCh:
				isReady = true
			default:
			}
		}
		if !isReady {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// metrics
	mux.Handle(s.MetricsPath, promHandler)

	// root
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := t.Execute(w, s); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// hot reload (POST /-/reload)
	mux.HandleFunc("/-/reload", instrument(apiReq, "/-/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// restrict to loopback for safety
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := mgr.Reload(); err != nil {
			http.Error(w, fmt.Sprintf("failed to reload config: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}))

	// Tasks API (authenticated + guarded)
	// Concurrency guard for task creation (hot-reloadable via atomic pointer)
	maxConc := 2
	if cfg0.Policy != nil && cfg0.Policy.MaxConcurrent > 0 {
		maxConc = cfg0.Policy.MaxConcurrent
	}
	var apiSem atomic.Value // *semaphore.Weighted
	apiSem.Store(semaphore.NewWeighted(int64(maxConc)))
	// Build policy guards from current config snapshot (will be reloaded on /-/reload call paths via mgr)
	// Note: we read cfg live inside handlers to always use latest policy/auth.

	// POST /v1/tasks/scan
	mux.HandleFunc(
		"/v1/tasks/scan",
		instrument(apiReq, "/v1/tasks/scan", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			cfg := mgr.Get()
			// Auth (Bearer or Basic)
			if !checkAuth(r, cfg.Auth) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// Client allow-list + rate limit
			if !allowClientWithProxies(r, cfg.Policy, trustedProxies) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if guards != nil && !guards.Allow(r) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			// concurrency
			sem := apiSem.Load().(*semaphore.Weighted)
			if err := sem.Acquire(r.Context(), 1); err != nil {
				http.Error(w, "request cancelled", http.StatusRequestTimeout)
				return
			}
			defer sem.Release(1)
			// Decode request
			var req struct {
				Targets     []string `json:"targets"`
				Ports       string   `json:"ports"`
				Protocol    string   `json:"protocol"`
				Module      string   `json:"module"`
				MaxCIDRSize int      `json:"max_cidr_size"`
				Timeout     string   `json:"timeout"`
				DedupeKey   string   `json:"dedupe_key"`
				Priority    string   `json:"priority"`
				Retries     int      `json:"retries"`
			}
			if !decodeJSON(w, r, &req, 1<<20) {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if len(req.Targets) == 0 || strings.TrimSpace(req.Ports) == "" {
				http.Error(w, "targets and ports are required", http.StatusBadRequest)
				return
			}
			proto := strings.ToLower(strings.TrimSpace(req.Protocol))
			if proto == "" {
				proto = "tcp"
			}
			if !portsRe.MatchString(req.Ports) {
				http.Error(w, "invalid ports syntax", http.StatusBadRequest)
				return
			}
			// Series guard
			ipCount := estimateIPCount(req.Targets)
			portCount, ok := estimatePortCount(req.Ports)
			if !ok || portCount <= 0 {
				http.Error(w, "invalid ports", http.StatusBadRequest)
				return
			}
			if cfg.Policy != nil && cfg.Policy.SeriesLimit > 0 {
				if ipCount*portCount > cfg.Policy.SeriesLimit {
					http.Error(w, "series limit exceeded", http.StatusBadRequest)
					return
				}
			}
			// Fanout and backpressure
			maxCIDR := cfg.Scheduler.DefaultMaxCIDRSize
			if req.MaxCIDRSize > 0 {
				maxCIDR = req.MaxCIDRSize
			}
			subScans := estimateSubScanFanout(req.Targets, maxCIDR)
			if subScans <= 0 {
				http.Error(w, "no work to enqueue", http.StatusBadRequest)
				return
			}
			pending := 0
			if prio != nil {
				pending = prio.Pending()
			}
			if cap(workerQueue)-(len(workerQueue)+pending) < subScans {
				http.Error(w, "queue full", http.StatusTooManyRequests)
				return
			}
			// Create task record (dedupe respected)
			rec, created := tm.Create(subScans, strings.TrimSpace(req.DedupeKey))
			accepted := created
			// Compute timeout override
			timeoutSec := 0
			if strings.TrimSpace(req.Timeout) != "" {
				if d, err := time.ParseDuration(req.Timeout); err == nil && d > 0 {
					timeoutSec = int(d.Seconds())
				}
			}
			// Enqueue subtasks
			for _, tgt := range req.Targets {
				subs, err := scanner.SplitIntoSubnets(tgt, maxCIDR)
				if err != nil {
					continue
				}
				for _, sub := range subs {
					st := scanner.ScanTask{
						Target:                 sub,
						PortRange:              req.Ports,
						Protocol:               proto,
						TaskID:                 rec.ID,
						Module:                 req.Module,
						MaxCIDRSizeOverride:    maxCIDR,
						TimeoutOverrideSeconds: timeoutSec,
						MaxAttempts:            req.Retries,
					}
					ok := false
					if prio != nil {
						p := strings.ToLower(strings.TrimSpace(req.Priority))
						ok = prio.Enqueue(p, st)
					} else {
						select {
						case workerQueue <- st:
							ok = true
						default:
							ok = false
						}
					}
					if !ok {
						http.Error(w, "queue full", http.StatusTooManyRequests)
						return
					}
				}
			}
			mc.UpdateTaskQueueSize(len(workerQueue) + pending)
			mc.IncTasksCreated(nonEmpty(req.Module, "default"))
			mc.SetOldestPendingAge(tm.OldestPendingAge())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"task_id": rec.ID, "accepted": accepted})
		}),
	)

	// GET /v1/tasks/{id} and POST /v1/tasks/{id}/cancel
	mux.HandleFunc("/v1/tasks/", instrument(apiReq, "/v1/tasks/*", func(w http.ResponseWriter, r *http.Request) {
		cfg := mgr.Get()
		if !checkAuth(r, cfg.Auth) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !allowClientWithProxies(r, cfg.Policy, trustedProxies) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 3 || parts[0] != "v1" || parts[1] != "tasks" {
			http.NotFound(w, r)
			return
		}
		id := parts[2]
		if r.Method == http.MethodGet && len(parts) == 3 {
			rec := tm.Get(id)
			if rec == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rec)
			return
		}
		if r.Method == http.MethodPost && len(parts) == 4 && parts[3] == "cancel" {
			ok := tm.Cancel(id)
			if !ok {
				http.Error(w, "cannot cancel", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		http.NotFound(w, r)
	}))

	// GET /v1/tasks?state=...&limit=N
	mux.HandleFunc("/v1/tasks", instrument(apiReq, "/v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cfg := mgr.Get()
		if !checkAuth(r, cfg.Auth) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !allowClientWithProxies(r, cfg.Policy, trustedProxies) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		q := r.URL.Query()
		st := strings.TrimSpace(q.Get("state"))
		lim := 0
		if v := strings.TrimSpace(q.Get("limit")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				lim = n
			}
		}
		list := tm.List(st, lim)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	}))

	srv := &http.Server{
		Addr:              ":" + s.ListenPort,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      2 * time.Minute,
	}

	// flip readiness
	go func() {
		time.Sleep(200 * time.Millisecond)
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}()

	// Allow components to react to reload: rebuild guards, proxies and concurrency semaphore
	mgr.AddOnReload(func(old, newCfg *cfgpkg.Config) {
		// Rebuild guards
		if newCfg.Policy != nil && newCfg.Policy.RateLimitRPS > 0 {
			guards = NewRateGuards(
				newCfg.Policy.RateLimitRPS,
				newCfg.Policy.RateBurst,
				10*time.Minute,
				true,
			)
		} else {
			guards = nil
		}
		// Recompute trusted proxies
		trustedProxies = nil
		if len(newCfg.Server.TrustedProxiesCIDRs) > 0 {
			for _, c := range newCfg.Server.TrustedProxiesCIDRs {
				if _, nw, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && nw != nil {
					trustedProxies = append(trustedProxies, nw)
				}
			}
		}
		// Swap concurrency semaphore
		m := 2
		if newCfg.Policy != nil && newCfg.Policy.MaxConcurrent > 0 {
			m = newCfg.Policy.MaxConcurrent
		}
		apiSem.Store(semaphore.NewWeighted(int64(m)))
	})

	return srv
}

func nonEmpty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// safe JSON decoder: limits body size and disallows unknown fields
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return false
	}
	return true
}

// status writer captures status code
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) { sw.status = code; sw.ResponseWriter.WriteHeader(code) }

// instrument wraps a handler to record requests per route/method/status code
func instrument(cv *prometheus.CounterVec, route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next(sw, r)
		code := strconv.Itoa(sw.status)
		if cv != nil {
			cv.WithLabelValues(route, r.Method, code).Inc()
		}
	}
}

func checkAuth(r *http.Request, auth *cfgpkg.AuthConfig) bool {
	if auth == nil {
		return true
	}
	// Bearer
	if strings.TrimSpace(auth.BearerToken) != "" {
		ah := r.Header.Get("Authorization")
		if strings.HasPrefix(ah, "Bearer ") &&
			strings.TrimSpace(strings.TrimPrefix(ah, "Bearer ")) == auth.BearerToken {
			return true
		}
	}
	// Basic
	if auth.Basic.Username != "" || auth.Basic.Password != "" {
		u, p, ok := r.BasicAuth()
		if ok && u == auth.Basic.Username && p == auth.Basic.Password {
			return true
		}
	}
	// If auth is present but empty, deny by default (stricter default)
	return false
}

// policy helpers
func allowClientWithProxies(r *http.Request, p *cfgpkg.PolicyConfig, proxies []*net.IPNet) bool {
	if p == nil || len(p.ClientAllowCIDRs) == 0 {
		return true
	}
	host := clientIPFromRequest(r, proxies)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range p.ClientAllowCIDRs {
		_, nw, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil && nw != nil && nw.Contains(ip) {
			return true
		}
	}
	return false
}

// removed global rate limiter (replaced by RateGuards)

// estimate helpers (duplicated small helpers to avoid exporting internals)
func estimatePortCount(ports string) (int, bool) {
	tokens := strings.Split(ports, ",")
	total := 0
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return 0, false
		}
		if strings.Contains(tok, "-") {
			pp := strings.SplitN(tok, "-", 2)
			if len(pp) != 2 {
				return 0, false
			}
			a, errA := strconv.Atoi(pp[0])
			b, errB := strconv.Atoi(pp[1])
			if errA != nil || errB != nil || a < 1 || b < 1 || a > 65535 || b > 65535 || a > b {
				return 0, false
			}
			total += b - a + 1
		} else {
			p, err := strconv.Atoi(tok)
			if err != nil || p < 1 || p > 65535 {
				return 0, false
			}
			total++
		}
	}
	return total, true
}

func estimateIPCount(targets []string) int {
	total := 0
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if ip := net.ParseIP(t); ip != nil {
			total++
			continue
		}
		_, nw, err := net.ParseCIDR(t)
		if err != nil || nw == nil {
			continue
		}
		ones, bits := nw.Mask.Size()
		span := bits - ones
		if span >= 31 {
			return 1 << 30
		}
		total += 1 << span
		if total < 0 {
			return 1 << 30
		}
	}
	return total
}

func estimateSubScanFanout(targets []string, maxCIDRSize int) int {
	total := 0
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if ip := net.ParseIP(t); ip != nil {
			total++
			continue
		}
		_, nw, err := net.ParseCIDR(t)
		if err != nil || nw == nil {
			continue
		}
		ones, _ := nw.Mask.Size()
		if ones >= maxCIDRSize {
			total++
		} else {
			span := maxCIDRSize - ones
			if span >= 31 {
				total += 1 << 30
			} else {
				total += 1 << span
			}
		}
		if total < 0 {
			return 1 << 30
		}
	}
	return total
}

func clientIPFromRequest(r *http.Request, proxies []*net.IPNet) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || ipInAny(ip, proxies)) {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			p := strings.TrimSpace(parts[0])
			return p
		}
	}
	return host
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, nw := range nets {
		if nw.Contains(ip) {
			return true
		}
	}
	return false
}
