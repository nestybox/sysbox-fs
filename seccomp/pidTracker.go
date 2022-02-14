//
// Copyright 2019-2022 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package seccomp

import (
	"sync"
)

// The seccompNotifPidTracker helps serialize the processing of seccomp
// notifications per thread, so that only one seccomp notif is processed per
// thread-id (pid) at any given time.

type seccompNotifPidTracker struct {
	mu       sync.RWMutex
	pidTable map[uint32]*pidData
}

type pidData struct {
	refcnt int
	mu     sync.Mutex
}

func newSeccompNotifPidTracker() *seccompNotifPidTracker {
	return &seccompNotifPidTracker{
		pidTable: make(map[uint32]*pidData),
	}
}

// Adds the given pid to the tracker's table of tracked pids.
func (t *seccompNotifPidTracker) track(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If pid not present in pidTable, add entry with count = 1; else increase
	// the pid's refcount.
	pd, ok := t.pidTable[pid]
	if !ok {
		t.pidTable[pid] = &pidData{refcnt: 1}
	} else {
		pd.refcnt++
		t.pidTable[pid] = pd
	}
}

// Removes the given pid from the tracker's table of tracked pids.
func (t *seccompNotifPidTracker) untrack(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	pd, ok := t.pidTable[pid]
	if !ok {
		return
	}

	pd.refcnt--

	if pd.refcnt > 0 {
		t.pidTable[pid] = pd
	} else {
		delete(t.pidTable, pid)
	}
}

// Requests a lock on the given pid. Blocks if another process has the lock.
func (t *seccompNotifPidTracker) Lock(pid uint32) {
	t.track(pid)

	t.mu.RLock()
	pd, ok := t.pidTable[pid]
	t.mu.RUnlock()
	if !ok {
		return
	}

	// Grab the per-pid lock
	pd.mu.Lock()
}

// Releases the lock on the given pid. Must be called after Lock().
func (t *seccompNotifPidTracker) Unlock(pid uint32) {
	t.mu.RLock()
	pd, ok := t.pidTable[pid]
	t.mu.RUnlock()
	if !ok {
		return
	}

	// Release the per-pid lock
	pd.mu.Unlock()

	t.untrack(pid)
}
