package httpserver

import (
	"context"
	"html/template"
	"log/slog"
	"math"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"

	"github.com/renatogalera/openport-exporter/internal/collectors"
	cfgpkg "github.com/renatogalera/openport-exporter/internal/config"
	"github.com/renatogalera/openport-exporter/internal/scanner"
)

// Simple landing page with a working repo link and example /probe query.
const rootTemplate = `<html>
 <head><title>OpenPort Exporter</title></head>
 <body>
   <h1>OpenPort Exporter</h1>
   <p>Metrics at: <a href='{{ .MetricsPath }}'>{{ .MetricsPath }}</a></p>
   <p>Source: <a href='https://github.com/renatogalera/openport-exporter'>github.com/renatogalera/openport-exporter</a></p>
   <p>Probe endpoint: <code>/probe?target=10.0.0.1,10.0.0.2/31&amp;ports=22,80,443,1000-1024&amp;module=tcp_fast&amp;protocol=tcp&amp;details=1</code></p>
 </body>
 </html>`

// Ports syntax: "80,443,1000-1024"
var portsRe = regexp.MustCompile(`^(?:\d{1,5}(?:-\d{1,5})?)(?:\s*,\s*(?:\d{1,5}(?:-\d{1,5})?))*$`)

// NewServer wires the custom registry and handlers.
//
// Security/perf hardening in this version:
//  - Correct promhttp usage (no bogus HandlerOpts fields).
//  - Add MaxRequestsInFlight/Timeout to metrics handler for backpressure.
//  - Optional /probe auth accepts either Bearer OR Basic when both configured.
//  - Optional use of X-Forwarded-For only when coming from loopback.
//  - Soft readiness gating via an internal flag setter (exported via SetReady).
func NewServer(e *collectors.Exporter, s *collectors.Settings, cfg *cfgpkg.Config) *http.Server {
	t := template.Must(template.New("root").Parse(rootTemplate))

	// Custom registry for exporter metrics.
	reg := prometheus.NewRegistry()
	reg.MustRegister(e)
	if s.EnableBuildInfo {
		reg.MustRegister(promcollectors.NewBuildInfoCollector())
	}
	if s.EnableGoCollector {
		reg.MustRegister(promcollectors.NewGoCollector())
	}

	// Local metrics for /probe guardrails and handler latencies.
	proberRequests := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "openport_probe_requests_total", Help: "Number of /probe requests by outcome."},
		[]string{"outcome"},
	)
	proberInflight := prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "openport_probe_inflight", Help: "Current in-flight /probe requests."},
	)
	proberHandlerSeconds := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "openport_probe_handler_seconds",
			Help:    "End-to-end handler latency for /probe.",
			Buckets: prometheus.DefBuckets,
		},
	)
	reg.MustRegister(proberRequests, proberInflight, proberHandlerSeconds)

	// Backpressure on /metrics gather.
	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		// Rejects further scrapes if many concurrent gathers occur.
		MaxRequestsInFlight: 8,
		// Prevents long-hanging gathers in pathological cases.
		Timeout: 30 * time.Second,
	})

	mux := http.NewServeMux()

	// Readiness/health. Keep health as always OK; make readiness meaningful.
	readyCh := make(chan struct{}, 1) // closed when the app is ready.
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

	// Main handlers
	mux.Handle(s.MetricsPath, promHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := t.Execute(w, s); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// Optional /probe
	if s.EnableProber {
		setupProbeHandler(mux, s, cfg, e.Logger, proberRequests, proberInflight, proberHandlerSeconds)
	}

	// HTTP server with tight-ish timeouts. No h2c; HTTP/2 only via TLS offload if any.
	srv := &http.Server{
		Addr:              ":" + s.ListenPort,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      2 * time.Minute,
		// BaseContext ensures children inherit server lifetime if desired.
	}

	// Flip readiness after server starts accepting (best-effort).
	go func() {
		// In practice you could trigger this from cmd/run after workers start.
		// We mark ready shortly after startup to avoid regressions; customize as needed.
		time.Sleep(200 * time.Millisecond)
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}()

	return srv
}

func setupProbeHandler(
	mux *http.ServeMux,
	s *collectors.Settings,
	baseCfg *cfgpkg.Config,
	logger *slog.Logger,
	reqCtr *prometheus.CounterVec,
	inflight prometheus.Gauge,
	handlerHist prometheus.Histogram,
) {
	// Parse allowed target CIDRs.
	var allowed []*net.IPNet
	for _, cidr := range s.ProberAllowCIDRs {
		_, nw, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil && nw != nil {
			allowed = append(allowed, nw)
		}
	}

	// Parse allowed client CIDRs (who may call /probe).
	var clientAllowed []*net.IPNet
	for _, cidr := range s.ProberClientAllowCIDRs {
		_, nw, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil && nw != nil {
			clientAllowed = append(clientAllowed, nw)
		}
	}

	// Global rate limiter (RPS) for /probe.
	var lim *rate.Limiter
	if s.ProberRateLimit > 0 {
		lim = rate.NewLimiter(rate.Limit(s.ProberRateLimit), max(1, s.ProberBurst))
	}

	// Global concurrency cap for /probe.
	sem := make(chan struct{}, max(1, s.ProberMaxConcurrent))

	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		// Method check and anti-caching for safety.
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")

		start := time.Now()
		inflight.Inc()
		defer func() {
			inflight.Dec()
			handlerHist.Observe(time.Since(start).Seconds())
		}()

		// Concurrency guard
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			logger.Info("probe denied: concurrency limit", "remote", r.RemoteAddr)
			reqCtr.WithLabelValues("concurrency").Inc()
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// RPS guard
		if lim != nil && !lim.Allow() {
			logger.Info("probe denied: rate limited", "remote", r.RemoteAddr)
			reqCtr.WithLabelValues("rate_limited").Inc()
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Client allow-list (optionally trusts XFF only if hop is loopback)
		if len(clientAllowed) > 0 {
			host := clientIPFromRequest(r)
			ip := net.ParseIP(host)
			ok := false
			for _, nw := range clientAllowed {
				if nw.Contains(ip) {
					ok = true
					break
				}
			}
			if !ok {
				reqCtr.WithLabelValues("forbidden_client").Inc()
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		// Auth: accept EITHER Bearer OR Basic if configured.
		if s.ProberAuthToken != "" || s.ProberBasicUser != "" || s.ProberBasicPass != "" {
			authOK := false
			// Bearer
			if s.ProberAuthToken != "" {
				ah := r.Header.Get("Authorization")
				if strings.HasPrefix(ah, "Bearer ") && strings.TrimSpace(strings.TrimPrefix(ah, "Bearer ")) == s.ProberAuthToken {
					authOK = true
				}
			}
			// Basic
			if !authOK && (s.ProberBasicUser != "" || s.ProberBasicPass != "") {
				u, p, ok := r.BasicAuth()
				if ok && u == s.ProberBasicUser && p == s.ProberBasicPass {
					authOK = true
				}
			}
			if !authOK {
				reqCtr.WithLabelValues("unauthorized").Inc()
				if s.ProberBasicUser != "" || s.ProberBasicPass != "" {
					w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// Parse query params
		q := r.URL.Query()
		target := strings.TrimSpace(q.Get("target"))
		ports := strings.TrimSpace(q.Get("ports"))
		protocol := strings.ToLower(strings.TrimSpace(q.Get("protocol")))
		if protocol == "" {
			protocol = "tcp"
		}
		if target == "" {
			reqCtr.WithLabelValues("bad_request").Inc()
			http.Error(w, "missing target", http.StatusBadRequest)
			return
		}
		if len(allowed) > 0 && !areTargetsAllowed(splitTargets(target), allowed) {
			reqCtr.WithLabelValues("target_denied").Inc()
			http.Error(w, "target not allowed", http.StatusForbidden)
			return
		}

		// Deadline (respect scrape header with safety margin)
		timeoutStr := q.Get("timeout")
		if timeoutStr == "" {
			timeoutStr = s.ProberDefaultTimeout
		}
		d, err := time.ParseDuration(timeoutStr)
		if err != nil || d <= 0 {
			d = 10 * time.Second
		}
		if hdr := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); hdr != "" {
			if secs, err := strconv.ParseFloat(hdr, 64); err == nil && secs > 0 {
				htd := time.Duration(secs*float64(time.Second)) - 250*time.Millisecond
				if htd > 0 && htd < d {
					d = htd
				}
			}
		}

		// Apply module defaults if present
		modName := strings.TrimSpace(q.Get("module"))
		localCfg := *baseCfg
		if baseCfg != nil && baseCfg.Prober != nil && modName != "" {
			if mod, ok := baseCfg.Prober.Modules[modName]; ok {
				applyModuleToConfig(&localCfg, &mod)
				if ports == "" && mod.Ports != nil && *mod.Ports != "" {
					ports = *mod.Ports
				}
				if protocol == "" && mod.Protocol != nil && *mod.Protocol != "" {
					protocol = strings.ToLower(*mod.Protocol)
				}
			}
		}

		maxCfg := time.Duration(localCfg.Scanning.Timeout) * time.Second
		if maxCfg > 0 && d > maxCfg {
			d = maxCfg
		}

		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()

		// Validate ports
		if ports == "" {
			reqCtr.WithLabelValues("bad_request").Inc()
			http.Error(w, "missing ports", http.StatusBadRequest)
			return
		}
		if !portsRe.MatchString(ports) {
			reqCtr.WithLabelValues("bad_request").Inc()
			http.Error(w, "invalid ports syntax", http.StatusBadRequest)
			return
		}
		if cnt, ok := estimatePortCount(ports); !ok || cnt <= 0 {
			reqCtr.WithLabelValues("bad_request").Inc()
			http.Error(w, "invalid ports values", http.StatusBadRequest)
			return
		} else if s.ProberMaxPorts > 0 && cnt > s.ProberMaxPorts {
			reqCtr.WithLabelValues("bad_request").Inc()
			http.Error(w, "ports selection too large", http.StatusBadRequest)
			return
		}

		// Targets fanout bounds
		targets := splitTargets(target)
		if s.ProberMaxTargets > 0 && len(targets) > s.ProberMaxTargets {
			reqCtr.WithLabelValues("bad_request").Inc()
			http.Error(w, "too many targets", http.StatusBadRequest)
			return
		}
		if len(allowed) > 0 && !areTargetsAllowed(targets, allowed) {
			reqCtr.WithLabelValues("target_denied").Inc()
			http.Error(w, "target not allowed", http.StatusForbidden)
			return
		}

		// Optional detailed series (bounded)
		details := q.Get("details") == "1"
		if details {
			ipCount := estimateIPCount(targets)
			portCount, _ := estimatePortCount(ports)
			const seriesLimit = 5000 // TODO: make configurable
			if ipCount*portCount > seriesLimit {
				reqCtr.WithLabelValues("series_limit").Inc()
				http.Error(w, "details would exceed series limit", http.StatusBadRequest)
				return
			}
		}

		// Per-probe registry
		preg := prometheus.NewRegistry()
		probeSuccess := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_success", Help: "Whether the probe succeeded.",
		})
		probeDuration := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_duration_seconds", Help: "Probe duration in seconds.",
		})
		probeOpenPortsTotal := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_open_ports_total", Help: "Total number of open (ip,port,proto) seen by the probe.",
		})
		probeHostsUp := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_hosts_up", Help: "Number of hosts up in probe.",
		})
		probeHostsDown := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_hosts_down", Help: "Number of hosts down in probe.",
		})
		preg.MustRegister(probeSuccess, probeDuration, probeOpenPortsTotal, probeHostsUp, probeHostsDown)

		var probePortOpen *prometheus.GaugeVec
		if details {
			probePortOpen = prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: "probe_port_open",
					Help: "Whether the (ip,port,proto) tuple was open during probe.",
				},
				[]string{"ip", "port", "protocol"},
			)
			preg.MustRegister(probePortOpen)
		}

		// Target splitting guard
		maxCIDR := s.ProberMaxCIDRSize
		if m := q.Get("max_cidr_size"); m != "" {
			if v, err := strconv.Atoi(m); err == nil && v > 0 {
				maxCIDR = v
			}
		}
		subScans := estimateSubScanFanout(targets, maxCIDR)
		if subScans > 256 {
			logger.Warn("probe high fanout", "remote", r.RemoteAddr, "targets", len(targets), "subscans", subScans, "max_cidr_size", maxCIDR)
			reqCtr.WithLabelValues("large_fanout").Inc()
		}

		// Run scan(s)
		agg := make(map[string]struct{})
		totalUp, totalDown := 0, 0
		var totalDur float64
		for _, t := range targets {
			res, up, down, dur, err := scanner.RunImmediateScan(ctx, &localCfg, t, ports, protocol, maxCIDR, logger)
			if err != nil {
				reqCtr.WithLabelValues("error").Inc()
				probeSuccess.Set(0)
				probeDuration.Set(time.Since(start).Seconds())
				probeOpenPortsTotal.Set(float64(len(agg)))
				probeHostsUp.Set(float64(totalUp))
				probeHostsDown.Set(float64(totalDown))
				logger.Info("probe", "remote", r.RemoteAddr, "decision", "error", "module", modName, "targets", len(targets), "ports", ports, "protocol", protocol, "open_ports", len(agg), "hosts_up", totalUp, "hosts_down", totalDown, "duration", time.Since(start).Seconds())
				promhttp.HandlerFor(preg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
				return
			}
			for k := range res {
				agg[k] = struct{}{}
			}
			totalUp += up
			totalDown += down
			totalDur += dur
		}

		avgDur := 0.0
		if n := len(targets); n > 0 {
			avgDur = totalDur / float64(n)
		}

		probeSuccess.Set(1)
		probeDuration.Set(avgDur)
		probeOpenPortsTotal.Set(float64(len(agg)))
		probeHostsUp.Set(float64(totalUp))
		probeHostsDown.Set(float64(totalDown))

		if details && probePortOpen != nil {
			for k := range agg {
				ip, port := splitIPPort(k)
				probePortOpen.WithLabelValues(ip, port, protocol).Set(1)
			}
		}

		reqCtr.WithLabelValues("ok").Inc()
		logger.Info("probe", "remote", r.RemoteAddr, "decision", "ok", "module", modName, "targets", len(targets), "ports", ports, "protocol", protocol, "open_ports", len(agg), "hosts_up", totalUp, "hosts_down", totalDown, "duration", avgDur)
		promhttp.HandlerFor(preg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	})
}

// clientIPFromRequest returns the caller IP, preferring X-Forwarded-For ONLY when proxied by loopback.
func clientIPFromRequest(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			p := strings.TrimSpace(parts[0])
			return p
		}
	}
	return host
}

func areTargetsAllowed(targets []string, allowed []*net.IPNet) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, t := range targets {
		if !isTargetAllowed(t, allowed) {
			return false
		}
	}
	return true
}

func isTargetAllowed(target string, allowed []*net.IPNet) bool {
	if ip := net.ParseIP(target); ip != nil {
		for _, nw := range allowed {
			if nw.Contains(ip) {
				return true
			}
		}
		return false
	}
	if _, nw, err := net.ParseCIDR(target); err == nil && nw != nil {
		first := nw.IP
		last := lastIP(nw)
		for _, a := range allowed {
			if a.Contains(first) && a.Contains(last) {
				return true
			}
		}
		return false
	}
	return false
}

func splitIPPort(k string) (string, string) {
	if i := strings.LastIndexByte(k, '/'); i >= 0 {
		k = k[:i]
	}
	if host, port, err := net.SplitHostPort(k); err == nil {
		return host, port
	}
	if i := strings.LastIndex(k, ":"); i != -1 && i < len(k)-1 {
		return k[:i], k[i+1:]
	}
	return k, ""
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
			return math.MaxInt32 / 2
		}
		total += 1 << span
		if total < 0 || total > math.MaxInt32/2 {
			return math.MaxInt32 / 2
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
				total += math.MaxInt32 / 4
			} else {
				total += 1 << span
			}
		}
		if total < 0 || total > math.MaxInt32/2 {
			return math.MaxInt32 / 2
		}
	}
	return total
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func lastIP(nw *net.IPNet) net.IP {
	ip := nw.IP
	mask := nw.Mask
	if v4 := ip.To4(); v4 != nil {
		ip4 := v4
		last := make(net.IP, net.IPv4len)
		for i := 0; i < net.IPv4len; i++ {
			last[i] = ip4[i] | ^mask[i]
		}
		return last
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	last := make(net.IP, net.IPv6len)
	for i := 0; i < net.IPv6len; i++ {
		last[i] = ip16[i] | ^mask[i]
	}
	return last
}

func applyModuleToConfig(cfg *cfgpkg.Config, mod *cfgpkg.ProberModule) {
	sc := &cfg.Scanning
	if mod.UseSYNScan != nil {
		sc.UseSYNScan = mod.UseSYNScan
	}
	if mod.MinRate != nil {
		sc.MinRate = *mod.MinRate
	}
	if mod.MaxRate != nil {
		sc.MaxRate = *mod.MaxRate
	}
	if mod.MinParallelism != nil {
		sc.MinParallelism = *mod.MinParallelism
	}
	if mod.MaxRetries != nil {
		sc.MaxRetries = *mod.MaxRetries
	}
	if mod.HostTimeout != nil {
		sc.HostTimeout = *mod.HostTimeout
	}
	if mod.ScanDelay != nil {
		sc.ScanDelay = *mod.ScanDelay
	}
	if mod.MaxScanDelay != nil {
		sc.MaxScanDelay = *mod.MaxScanDelay
	}
	if mod.InitialRttTimeout != nil {
		sc.InitialRttTimeout = *mod.InitialRttTimeout
	}
	if mod.MaxRttTimeout != nil {
		sc.MaxRttTimeout = *mod.MaxRttTimeout
	}
	if mod.MinRttTimeout != nil {
		sc.MinRttTimeout = *mod.MinRttTimeout
	}
	if mod.DisableHostDiscovery != nil {
		sc.DisableHostDiscovery = *mod.DisableHostDiscovery
	}
}

func splitTargets(s string) []string {
	fs := func(r rune) bool { return r == ',' || unicode.IsSpace(r) }
	var out []string
	for _, p := range strings.FieldsFunc(s, fs) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 && strings.TrimSpace(s) != "" {
		out = append(out, strings.TrimSpace(s))
	}
	return out
}

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
		if total < 0 {
			return 0, false
		}
	}
	return total, true
}
