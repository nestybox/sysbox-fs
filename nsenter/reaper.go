//
// Copyright 2019-2020 Nestybox, Inc.
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

package nsenter

import (
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

type zombieReaper struct {
	mu     sync.RWMutex
	signal chan bool
}

func newZombieReaper() *zombieReaper {

	zr := &zombieReaper{
		signal: make(chan bool),
	}

	go reaper(zr.signal, &zr.mu)
	return zr
}

func (zr *zombieReaper) nsenterStarted() {
	zr.mu.RLock()
}

func (zr *zombieReaper) nsenterEnded() {
	zr.mu.RUnlock()
}

func (zr *zombieReaper) nsenterReapReq() {
	select {
	case zr.signal <- true:
		logrus.Debugf("nsenter child reaping requested")
	default:
		// no action required (someone else has signaled already)
	}
}

// Go-routine that performs reaping
func reaper(signal chan bool, mu *sync.RWMutex) {
	var wstatus syscall.WaitStatus

	for {
		<-signal

		// Use TryLock instead of Lock to avoid blocking subsequent RLock
		// callers. Go's sync.RWMutex implements writer-preference: a pending
		// Lock() blocks all new RLock() calls. If an nsenter child triggers
		// a FUSE request back to sysbox-fs, the FUSE handler needs RLock to
		// start a new nsenter. A blocking Lock() here would prevent that
		// RLock, causing a deadlock. TryLock avoids this by simply skipping
		// the reap cycle when nsenters are active
		for !mu.TryLock() {
			time.Sleep(time.Millisecond * 100)
		}
		for {
			// WNOHANG: if there is no child to reap, don't block
			wpid, err := syscall.Wait4(-1, &wstatus, syscall.WNOHANG, nil)
			if err != nil || wpid == 0 {
				logrus.Infof("reaper: nothing to reap")
				break
			}

			logrus.Infof("reaper: reaped pid %d", wpid)
		}
		mu.Unlock()
	}
}
