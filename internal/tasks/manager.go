package tasks

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
)

// Summary holds compact task stats, no high-cardinality detail.
type Summary struct {
	HostsUp    int `json:"hosts_up"`
	HostsDown  int `json:"hosts_down"`
	OpenTuples int `json:"open_tuples"`
}

type Record struct {
	ID          string    `json:"task_id"`
	State       State     `json:"state"`
	SubmittedAt time.Time `json:"submitted_at"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
	Summary     Summary   `json:"summary"`
	Error       string    `json:"error"`

	// internal tracking
	subTotal int
	subDone  int
	cancelFn func()
}

// Manager tracks background tasks and provides dedupe windows.
type Manager struct {
	mu        sync.RWMutex
	tasks     map[string]*Record
	byState   map[State]map[string]struct{}
	dedupe    map[string]dedupeEntry
	dedupeTTL time.Duration
}

type dedupeEntry struct {
	id  string
	exp time.Time
}

func NewManager(dedupeTTL time.Duration) *Manager {
	return &Manager{
		tasks: make(map[string]*Record),
		byState: map[State]map[string]struct{}{
			StatePending:   {},
			StateRunning:   {},
			StateSucceeded: {},
			StateFailed:    {},
			StateCancelled: {},
		},
		dedupe:    make(map[string]dedupeEntry),
		dedupeTTL: dedupeTTL,
	}
}

func (m *Manager) genID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Create creates a new task record with N subtasks and optional dedupe key.
func (m *Manager) Create(subCount int, dedupeKey string) (*Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if dedupeKey != "" {
		if ent, ok := m.dedupe[dedupeKey]; ok {
			if time.Now().Before(ent.exp) {
				if r := m.tasks[ent.id]; r != nil {
					return r, false
				}
			}
		}
	}
	id := m.genID()
	rec := &Record{ID: id, State: StatePending, SubmittedAt: time.Now(), subTotal: subCount}
	m.tasks[id] = rec
	m.byState[StatePending][id] = struct{}{}
	if dedupeKey != "" && m.dedupeTTL > 0 {
		m.dedupe[dedupeKey] = dedupeEntry{id: id, exp: time.Now().Add(m.dedupeTTL)}
	}
	return rec, true
}

func (m *Manager) Start(id string, cancelFn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.tasks[id]; r != nil {
		if r.State == StatePending {
			delete(m.byState[StatePending], id)
			m.byState[StateRunning][id] = struct{}{}
			r.State = StateRunning
			r.StartedAt = time.Now()
		}
		r.cancelFn = cancelFn
	}
}

func (m *Manager) SubtaskDone(
	id string,
	hostsUp, hostsDown, openTuples int,
	err error,
) (completed bool, outcome string, durationSec float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.tasks[id]; r != nil {
		r.subDone++
		r.Summary.HostsUp += hostsUp
		r.Summary.HostsDown += hostsDown
		r.Summary.OpenTuples += openTuples
		if err != nil && r.Error == "" {
			r.Error = err.Error()
		}
		if r.subDone >= r.subTotal && r.State != StateCancelled {
			delete(m.byState[StateRunning], id)
			if r.Error == "" {
				m.byState[StateSucceeded][id] = struct{}{}
				r.State = StateSucceeded
				outcome = "success"
			} else {
				m.byState[StateFailed][id] = struct{}{}
				r.State = StateFailed
				outcome = "error"
			}
			r.FinishedAt = time.Now()
			r.cancelFn = nil
			completed = true
			if !r.StartedAt.IsZero() {
				durationSec = r.FinishedAt.Sub(r.StartedAt).Seconds()
			}
		}
	}
	return completed, outcome, durationSec
}

func (m *Manager) Cancel(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.tasks[id]; r != nil {
		if r.State == StateSucceeded || r.State == StateFailed || r.State == StateCancelled {
			return false
		}
		if r.cancelFn != nil {
			r.cancelFn()
		}
		// mark cancelled
		for st := range m.byState {
			delete(m.byState[st], id)
		}
		m.byState[StateCancelled][id] = struct{}{}
		r.State = StateCancelled
		r.FinishedAt = time.Now()
		r.cancelFn = nil
		return true
	}
	return false
}

func (m *Manager) Get(id string) *Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if r := m.tasks[id]; r != nil {
		cp := *r
		return &cp
	}
	return nil
}

func (m *Manager) List(state string, limit int) []*Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var ids []string
	if state == "" {
		for id := range m.tasks {
			ids = append(ids, id)
		}
	} else {
		st := State(state)
		for id := range m.byState[st] {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if limit <= 0 || limit > len(ids) {
		limit = len(ids)
	}
	out := make([]*Record, 0, limit)
	for i := 0; i < limit; i++ {
		if r := m.tasks[ids[i]]; r != nil {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out
}

// OldestPendingAge returns seconds since the oldest pending task was submitted, or 0 if none.
func (m *Manager) OldestPendingAge() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	oldest := time.Time{}
	for id := range m.byState[StatePending] {
		if r := m.tasks[id]; r != nil {
			if oldest.IsZero() || r.SubmittedAt.Before(oldest) {
				oldest = r.SubmittedAt
			}
		}
	}
	if oldest.IsZero() {
		return 0
	}
	return time.Since(oldest).Seconds()
}

// RunningCount returns current number of tasks in running state.
func (m *Manager) RunningCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byState[StateRunning])
}

// GC removes finished tasks by age and enforces a maximum number of records.
func (m *Manager) GC(maxRecords int, maxAge time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	// Remove by age
	for id, r := range m.tasks {
		if !r.FinishedAt.IsZero() && now.Sub(r.FinishedAt) > maxAge {
			delete(m.tasks, id)
			for st := range m.byState {
				delete(m.byState[st], id)
			}
		}
	}
	// Enforce max count (best-effort): drop oldest finished first
	if maxRecords > 0 && len(m.tasks) > maxRecords {
		type pair struct {
			id   string
			when time.Time
		}
		var fin []pair
		for id, r := range m.tasks {
			if !r.FinishedAt.IsZero() {
				fin = append(fin, pair{id, r.FinishedAt})
			}
		}
		// simple selection: oldest first
		sort.Slice(fin, func(i, j int) bool { return fin[i].when.Before(fin[j].when) })
		over := len(m.tasks) - maxRecords
		for i := 0; i < len(fin) && over > 0; i++ {
			id := fin[i].id
			delete(m.tasks, id)
			for st := range m.byState {
				delete(m.byState[st], id)
			}
			over--
		}
	}
}

// ParseCIDRs parses a list of CIDR strings into []*net.IPNet
func ParseCIDRs(list []string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range list {
		_, nw, err := net.ParseCIDR(strings.TrimSpace(c))
		if err == nil && nw != nil {
			out = append(out, nw)
		}
	}
	return out
}
