
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
