package priority

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/renatogalera/openport-exporter/internal/scanner"
)

type Queue struct {
	hi   chan scanner.ScanTask
	norm chan scanner.ScanTask
	low  chan scanner.ScanTask
	out  chan scanner.ScanTask
	stop chan struct{}
	pend atomic.Int64
	wg   sync.WaitGroup
}

func NewQueue(out chan scanner.ScanTask) *Queue {
	return &Queue{
		hi:   make(chan scanner.ScanTask, 1024),
		norm: make(chan scanner.ScanTask, 1024),
		low:  make(chan scanner.ScanTask, 1024),
		out:  out,
		stop: make(chan struct{}),
	}
}

func (q *Queue) Start() { q.wg.Add(1); go func() { defer q.wg.Done(); q.loop() }() }
func (q *Queue) Stop()  { close(q.stop) }
func (q *Queue) Wait()  { q.wg.Wait() }

func (q *Queue) loop() {
	for {
		select {
		case <-q.stop:
			return
		default:
		}
		// drain high, then normal, then low
		sent := false
		select {
		case t := <-q.hi:
			q.out <- t
			q.pend.Add(-1)
			sent = true
		default:
		}
		if !sent {
			select {
			case t := <-q.norm:
				q.out <- t
				q.pend.Add(-1)
				sent = true
			default:
			}
		}
		if !sent {
			select {
			case t := <-q.low:
				q.out <- t
				q.pend.Add(-1)
				sent = true
			default:
			}
		}
		if !sent {
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// Enqueue enfileira conforme prioridade: "high", "low" ou default normal.
func (q *Queue) Enqueue(priority string, t scanner.ScanTask) bool {
	switch priority {
	case "high":
		select {
		case q.hi <- t:
			q.pend.Add(1)
			return true
		default:
			return false
		}
	case "low":
		select {
		case q.low <- t:
			q.pend.Add(1)
			return true
		default:
			return false
		}
	default:
		select {
		case q.norm <- t:
			q.pend.Add(1)
			return true
		default:
			return false
		}
	}
}

func (q *Queue) Pending() int { return int(q.pend.Load()) }
