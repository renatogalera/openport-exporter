package httpserver

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateGuards struct {
	global *rate.Limiter
	byIP   map[string]*clientLimiter
	mu     sync.Mutex
	limit  rate.Limit
	burst  int
	ttl    time.Duration
}

type clientLimiter struct {
	*rate.Limiter
	last time.Time
}

func NewRateGuards(rps float64, burst int, ttl time.Duration, enableGlobal bool) *RateGuards {
	if burst <= 0 {
		burst = 1
	}
	g := &RateGuards{byIP: make(map[string]*clientLimiter, 1024), limit: rate.Limit(rps), burst: burst, ttl: ttl}
	if enableGlobal && rps > 0 {
		g.global = rate.NewLimiter(rate.Limit(rps), burst)
	}
	return g
}

func (g *RateGuards) Allow(r *http.Request) bool {
	if g == nil || g.limit <= 0 {
		return true
	}
	now := time.Now()
	if g.global != nil && !g.global.AllowN(now, 1) {
		return false
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}
	g.mu.Lock()
	cl, ok := g.byIP[host]
	if !ok {
		cl = &clientLimiter{Limiter: rate.NewLimiter(g.limit, g.burst), last: now}
		g.byIP[host] = cl
	} else {
		cl.last = now
	}
	g.mu.Unlock()
	if !cl.AllowN(now, 1) {
		return false
	}
	if now.Unix()%17 == 0 {
		go g.gc(now)
	}
	return true
}

func (g *RateGuards) gc(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, v := range g.byIP {
		if now.Sub(v.last) > g.ttl {
			delete(g.byIP, k)
		}
	}
}
