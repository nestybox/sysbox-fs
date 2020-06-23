//
// Copyright: (C) 2019-2020 Nestybox Inc.  All rights reserved.
//

package main

import (
	"io/ioutil"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {

	// Disable log generation during UT.
	logrus.SetOutput(ioutil.Discard)

	m.Run()
}
