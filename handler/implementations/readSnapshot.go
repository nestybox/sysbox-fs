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
	"io"
	"sync"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// Read snapshots of generated file content.
//
// Handlers that generate a file's content on every read (e.g., /proc/meminfo,
// whose values change constantly) would otherwise serve each read of a file
// from different content: a file read in several chunks could come out with
// a torn line, and the final read (the one expected to return 0 bytes) could
// return a stray tail when the content grew in between.
//
// To avoid this, the content generated at a reader's first read (offset 0)
// is kept and serves that reader's following reads, as the kernel does for
// its own procfs files. The snapshot is dropped when the reader reaches its
// end, or after snapshotTimeout when the reader stops reading before that.
//

const snapshotTimeout = 10 * time.Second

type snapshotKey struct {
	cntr string
	pid  uint32
	path string
}

type snapshot struct {
	content []byte
	taken   time.Time
}

var (
	snapshotsMu sync.Mutex
	snapshots   = make(map[snapshotKey]snapshot)
)

// readSnapshot serves the given read request from the reader's snapshot of
// the file at the given path, generating a new one with gen() when the
// request is at offset 0 or no snapshot is available.
func readSnapshot(
	req *domain.HandlerRequest,
	path string,
	gen func() ([]byte, error)) (int, error) {

	key := snapshotKey{pid: req.Pid, path: path}
	if req.Container != nil {
		key.cntr = req.Container.ID()
	}

	snapshotsMu.Lock()
	s, ok := snapshots[key]
	snapshotsMu.Unlock()

	if req.Offset == 0 || !ok || time.Since(s.taken) > snapshotTimeout {
		content, err := gen()
		if err != nil {
			return 0, err
		}
		s = snapshot{content: content, taken: time.Now()}
	}

	snapshotsMu.Lock()
	defer snapshotsMu.Unlock()

	if req.Offset >= int64(len(s.content)) {
		delete(snapshots, key)
		return 0, io.EOF
	}

	for k, v := range snapshots {
		if time.Since(v.taken) > snapshotTimeout {
			delete(snapshots, k)
		}
	}
	snapshots[key] = s

	return copy(req.Data, s.content[req.Offset:]), nil
}
