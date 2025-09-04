package scanner

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Test that ModuleLimiter enforces the configured parallelism cap per module.
func TestModuleLimiter_EnforcesLimitPerModule(t *testing.T) {
	ml := NewModuleLimiter()
	const workers = 8
	const limit = 1
	var wg sync.WaitGroup
	wg.Add(workers)

	var inCS int
	var maxInCS int
	var mu sync.Mutex

	enter := func() {
		mu.Lock()
		inCS++
		if inCS > maxInCS {
			maxInCS = inCS
		}
		mu.Unlock()
	}
	leave := func() { mu.Lock(); inCS--; mu.Unlock() }

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			ml.Ensure("modA", limit)
			release := ml.Acquire(context.Background(), "modA")
			defer release()
			enter()
			time.Sleep(10 * time.Millisecond)
			leave()
		}()
	}
	wg.Wait()
	if maxInCS > limit {
		t.Fatalf("critical section overlapped: max=%d > limit=%d", maxInCS, limit)
	}
}

// Ensure different modules have independent limits.
func TestModuleLimiter_IndependentModules(t *testing.T) {
	ml := NewModuleLimiter()
	var wg sync.WaitGroup
	wg.Add(2)

	// Each module with limit=1 can run concurrently if modules differ.
	var ranA, ranB bool
	start := make(chan struct{})

	go func() {
		defer wg.Done()
		<-start
		ml.Ensure("modA", 1)
		release := ml.Acquire(context.Background(), "modA")
		defer release()
		ranA = true
		time.Sleep(5 * time.Millisecond)
	}()
	go func() {
		defer wg.Done()
		<-start
		ml.Ensure("modB", 1)
		release := ml.Acquire(context.Background(), "modB")
		defer release()
		ranB = true
		time.Sleep(5 * time.Millisecond)
	}()
	close(start)
	wg.Wait()
	if !ranA || !ranB {
		t.Fatalf("expected both modules to run: A=%v B=%v", ranA, ranB)
	}
}
