package nsenter

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestReaperDoesNotBlockNewNsenter verifies that signaling the zombie reaper
// while an nsenter is active does not prevent a new nsenter from starting.
//
// This is a regression test for a deadlock caused by Go's sync.RWMutex
// writer-preference: when the reaper's Lock() was pending (waiting for an
// active nsenter's RLock to be released), all new RLock() callers — including
// FUSE handlers that needed to start their own nsenter — were blocked. If the
// active nsenter depended on one of those FUSE handlers to complete, the
// system deadlocked.
//
// The fix replaced Lock() with TryLock() in the reaper goroutine so it never
// registers a pending writer.
func TestReaperDoesNotBlockNewNsenter(t *testing.T) {
	zr := newZombieReaper()

	// Simulate an active nsenter holding the read lock.
	zr.nsenterStarted()

	// Signal the reaper multiple times over a few seconds to ensure at least
	// one signal arrives after the reaper's internal delay and the goroutine
	// reaches its lock attempt.
	for i := 0; i < 5; i++ {
		zr.nsenterReapReq()
		time.Sleep(500 * time.Millisecond)
	}

	// Try to start a second nsenter from a new goroutine. This calls RLock().
	// If the reaper registered a pending writer via Lock(), this blocks
	// indefinitely due to writer-preference.
	done := make(chan struct{})
	go func() {
		zr.nsenterStarted()
		zr.nsenterEnded()
		close(done)
	}()

	select {
	case <-done:
		// New nsenter started successfully — no writer-preference deadlock.
	case <-time.After(3 * time.Second):
		t.Fatal("nsenterStarted() blocked: reaper's pending write lock is starving new readers")
	}

	zr.nsenterEnded()
}

// TestReapProcessAsyncReleasesCallerPromptly verifies that reapProcessAsync
// does not block the caller. This is a regression test for a deadlock where
// SendRequest() called Process.Wait() synchronously while holding the reaper
// RLock. If the child's exit was delayed (e.g., by the kernel's fuse_flush on
// inherited FUSE file descriptors), the RLock was held indefinitely, preventing
// both the reaper and new FUSE handlers from making progress.
//
// The fix moved Process.Wait() into reapProcessAsync, which waits in a
// background goroutine so the caller can release the RLock immediately.
func TestReapProcessAsyncReleasesCallerPromptly(t *testing.T) {
	cmd := exec.Command("sleep", "3")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start child: %v", err)
	}
	defer cmd.Process.Kill()

	zr := newZombieReaper()

	// Simulate SendRequest's locking pattern: hold RLock, schedule async
	// reap, release RLock.
	zr.nsenterStarted()
	zr.reapProcessAsync(cmd.Process)
	zr.nsenterEnded()

	// The reaper must be able to acquire Lock immediately. If
	// reapProcessAsync blocked the caller (old behavior), the RLock would
	// still be held and this would time out.
	locked := make(chan struct{})
	go func() {
		zr.mu.Lock()
		zr.mu.Unlock()
		close(locked)
	}()

	select {
	case <-locked:
		// RLock was released before the child exited.
	case <-time.After(2 * time.Second):
		t.Fatal("reaper Lock blocked: reapProcessAsync is not releasing the caller promptly")
	}

	// The child must still be alive, proving we did not wait synchronously.
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("child exited prematurely: reapProcessAsync should not wait synchronously: %v", err)
	}
}
