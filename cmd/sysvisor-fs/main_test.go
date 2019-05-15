package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/nestybox/sysvisor/sysvisor-fs/domain"
)

func TestMain(m *testing.M) {

	// Disable log generation during UT.
	log.SetOutput(ioutil.Discard)

	// Activate UT mode.
	//unitTesting = true

	// Generate memory-based/mock FS during UT.
	//appFS = afero.NewMemMapFs()

	m.Run()
}

func Test_usage(t *testing.T) {
	tests := []struct {
		name string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usage()
		})
	}
}

func Test_signalHandler(t *testing.T) {
	type args struct {
		signalChan chan os.Signal
		fs         domain.FuseService
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signalHandler(tt.args.signalChan, tt.args.fs)
		})
	}
}

func Test_main(t *testing.T) {
	tests := []struct {
		name string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			main()
		})
	}
}
