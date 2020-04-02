//
// Copyright: (C) 2020 Nestybox Inc.  All rights reserved.
//

package nsenter

import (
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
)

const signalChanCap = 10

type zombieReaper struct {
	mu     sync.RWMutex
	signal chan bool
}

func newZombieReaper() *zombieReaper {

	zr := &zombieReaper{
		signal: make(chan bool, signalChanCap),
	}

	go reaper(zr.signal, zr.mu)

	return zr
}

func (zr *zombieReaper) nsenterStarted() {
	zr.mu.RLock()
}

func (zr *zombieReaper) nsenterEnded() {
	zr.mu.RUnlock()
}

func (zr *zombieReaper) nsenterReapReq() {
	zr.signal <- true
}

// Go-routine that performs reaping
func reaper(signal chan bool, mu sync.RWMutex) {
	var wstatus syscall.WaitStatus

	for {
		<-signal
		mu.Lock()

		wpid, err := syscall.Wait4(-1, &wstatus, 0, nil)
		if err != nil {
			logrus.Warn(err)
			mu.Unlock()
			continue
		}

		logrus.Debugf("Reaped zombie child pid %d", wpid)
		mu.Unlock()
	}
}
