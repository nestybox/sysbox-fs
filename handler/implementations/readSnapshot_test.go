//
// Copyright 2026 Nestybox, Inc.
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

package implementations

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

const testSnapshotPath = "/proc/test"

// growingContent returns a generator whose content grows on every call, the
// way a file such as /proc/meminfo changes between reads.
func growingContent(calls *int) func() ([]byte, error) {
	return func() ([]byte, error) {
		*calls++
		return []byte(fmt.Sprintf("value: %s\n", strings.Repeat("9", 8+*calls))), nil
	}
}

func readChunk(t *testing.T, pid uint32, offset int64, size int, gen func() ([]byte, error)) (string, error) {
	t.Helper()

	req := &domain.HandlerRequest{Pid: pid, Offset: offset, Data: make([]byte, size)}
	n, err := readSnapshot(req, testSnapshotPath, gen)
	return string(req.Data[:n]), err
}

func TestReadSnapshot(t *testing.T) {
	clear(snapshots)
	t.Cleanup(func() { clear(snapshots) })

	t.Run("chunked read sees the content of the first read", func(t *testing.T) {
		calls := 0
		gen := growingContent(&calls)
		var out strings.Builder

		for {
			chunk, err := readChunk(t, 1, int64(out.Len()), 4, gen)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("readSnapshot() failed: %v", err)
			}
			out.WriteString(chunk)
		}

		if want := "value: 999999999\n"; out.String() != want {
			t.Errorf("got %q, want %q", out.String(), want)
		}
		if calls != 1 {
			t.Errorf("content generated %d times, want 1", calls)
		}
		if _, ok := snapshots[snapshotKey{pid: 1, path: testSnapshotPath}]; ok {
			t.Errorf("snapshot kept after the reader reached its end")
		}
	})

	t.Run("final read returns no stray tail", func(t *testing.T) {
		calls := 0
		gen := growingContent(&calls)

		first, err := readChunk(t, 2, 0, 4096, gen)
		if err != nil {
			t.Fatalf("readSnapshot() failed: %v", err)
		}
		if tail, err := readChunk(t, 2, int64(len(first)), 4096, gen); err != io.EOF || tail != "" {
			t.Errorf("final read = %q, %v; want \"\", EOF", tail, err)
		}
	})

	t.Run("readers get their own snapshot", func(t *testing.T) {
		calls := 0
		gen := growingContent(&calls)

		a, _ := readChunk(t, 3, 0, 8, gen)
		b, _ := readChunk(t, 4, 0, 8, gen)
		aRest, _ := readChunk(t, 3, 8, 4096, gen)
		bRest, _ := readChunk(t, 4, 8, 4096, gen)

		if a+aRest != "value: 999999999\n" || b+bRest != "value: 9999999999\n" {
			t.Errorf("got %q and %q", a+aRest, b+bRest)
		}
	})

	t.Run("concurrent readers", func(t *testing.T) {
		var wg sync.WaitGroup
		for pid := uint32(100); pid < 132; pid++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				gen := func() ([]byte, error) { return []byte(fmt.Sprintf("pid: %d\n", pid)), nil }
				var out strings.Builder
				for {
					req := &domain.HandlerRequest{Pid: pid, Offset: int64(out.Len()), Data: make([]byte, 3)}
					n, err := readSnapshot(req, testSnapshotPath, gen)
					if err != nil {
						break
					}
					out.Write(req.Data[:n])
				}
				if want := fmt.Sprintf("pid: %d\n", pid); out.String() != want {
					t.Errorf("got %q, want %q", out.String(), want)
				}
			}()
		}
		wg.Wait()
	})

	t.Run("expired snapshot is regenerated", func(t *testing.T) {
		calls := 0
		gen := growingContent(&calls)
		snapshots[snapshotKey{pid: 5, path: testSnapshotPath}] = snapshot{
			content: []byte("stale\n"),
			taken:   time.Now().Add(-2 * snapshotTimeout),
		}

		if chunk, err := readChunk(t, 5, 2, 4096, gen); err != nil || chunk != "lue: 999999999\n" {
			t.Errorf("got %q, %v", chunk, err)
		}
	})

	t.Run("expired snapshots of other readers are dropped", func(t *testing.T) {
		calls := 0
		gen := growingContent(&calls)
		abandoned := snapshotKey{pid: 6, path: testSnapshotPath}
		snapshots[abandoned] = snapshot{content: []byte("abandoned\n"), taken: time.Now().Add(-2 * snapshotTimeout)}

		readChunk(t, 7, 0, 4, gen)

		if _, ok := snapshots[abandoned]; ok {
			t.Errorf("expired snapshot not dropped")
		}
	})
}
