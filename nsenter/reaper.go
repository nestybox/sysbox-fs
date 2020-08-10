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

		// Without this delay, sysbox-fs sometimes hangs the FUSE request that generates an
		// nsenter event that requires reaping. It's not clear why, but the tell-tale sign
		// of the hang is that the reaper is signaled but finds nothing to reap. This delay
		// mitigates this condition and the reaper finds something to reap.
		//
		// The delay chosen is one that allows nsenter agents to complete their tasks before
		// reaping occurs. Since the reaper runs in its own goroutine, this delay only
		// affects it (there is no undesired side-effect on nsenters).

		time.Sleep(time.Second)

		for {
			mu.Lock()

			// WNOHANG: if there is no child to reap, don't block
			wpid, err := syscall.Wait4(-1, &wstatus, syscall.WNOHANG, nil)
			if err != nil || wpid == 0 {
				logrus.Infof("reaper: nothing to reap")
				mu.Unlock()
				break
			}

			logrus.Infof("reaper: reaped pid %d", wpid)
			mu.Unlock()
		}
	}
}
