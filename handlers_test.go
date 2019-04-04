package main

import (
	"reflect"
	"testing"

	"bazil.org/fuse"
)

func Test_newHandlerMap(t *testing.T) {
	tests := []struct {
		name string
		want *handlerMap
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newHandlerMap(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newHandlerMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cpuInfoHandler_open(t *testing.T) {
	type args struct {
		cs    *containerState
		flags fuse.OpenFlags
	}
	tests := []struct {
		name    string
		h       *cpuInfoHandler
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.h.open(tt.args.cs, &tt.args.flags); (err != nil) != tt.wantErr {
				t.Errorf("cpuInfoHandler.open() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_cpuInfoHandler_read(t *testing.T) {
	type args struct {
		ionode ioNode
		cs     *containerState
		buf    []byte
		off    int64
	}
	tests := []struct {
		name    string
		h       *cpuInfoHandler
		args    args
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.read(tt.args.ionode, tt.args.cs, tt.args.buf, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("cpuInfoHandler.read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("cpuInfoHandler.read() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cpuInfoHandler_write(t *testing.T) {
	type args struct {
		ionode ioNode
		cs     *containerState
		buf    []byte
	}
	tests := []struct {
		name    string
		h       *cpuInfoHandler
		args    args
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.write(tt.args.ionode, tt.args.cs, tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("cpuInfoHandler.write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("cpuInfoHandler.write() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cpuInfoHandler_fetch(t *testing.T) {
	type args struct {
		ionode ioNode
		cs     *containerState
	}
	tests := []struct {
		name    string
		h       *cpuInfoHandler
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.fetch(tt.args.ionode, tt.args.cs)
			if (err != nil) != tt.wantErr {
				t.Errorf("cpuInfoHandler.fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("cpuInfoHandler.fetch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cpuInfoHandler_resource(t *testing.T) {
	tests := []struct {
		name string
		h    *cpuInfoHandler
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.resource(); got != tt.want {
				t.Errorf("cpuInfoHandler.resource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_uptimeHandler_open(t *testing.T) {
	type args struct {
		cs    *containerState
		flags fuse.OpenFlags
	}
	tests := []struct {
		name    string
		h       *uptimeHandler
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.h.open(tt.args.cs, &tt.args.flags); (err != nil) != tt.wantErr {
				t.Errorf("uptimeHandler.open() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_uptimeHandler_read(t *testing.T) {
	type args struct {
		ionode ioNode
		cs     *containerState
		buf    []byte
		off    int64
	}
	tests := []struct {
		name    string
		h       *uptimeHandler
		args    args
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.read(tt.args.ionode, tt.args.cs, tt.args.buf, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("uptimeHandler.read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("uptimeHandler.read() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_uptimeHandler_write(t *testing.T) {
	type args struct {
		ionode ioNode
		cs     *containerState
		buf    []byte
	}
	tests := []struct {
		name    string
		h       *uptimeHandler
		args    args
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.write(tt.args.ionode, tt.args.cs, tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("uptimeHandler.write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("uptimeHandler.write() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_uptimeHandler_fetch(t *testing.T) {
	type args struct {
		ionode ioNode
		cs     *containerState
	}
	tests := []struct {
		name    string
		h       *uptimeHandler
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.fetch(tt.args.ionode, tt.args.cs)
			if (err != nil) != tt.wantErr {
				t.Errorf("uptimeHandler.fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("uptimeHandler.fetch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_uptimeHandler_resource(t *testing.T) {
	tests := []struct {
		name string
		h    *uptimeHandler
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.resource(); got != tt.want {
				t.Errorf("uptimeHandler.resource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_nfConntrackMaxHandler_open(t *testing.T) {
	type args struct {
		cs    *containerState
		flags fuse.OpenFlags
	}
	tests := []struct {
		name    string
		h       *nfConntrackMaxHandler
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.h.open(tt.args.cs, &tt.args.flags); (err != nil) != tt.wantErr {
				t.Errorf("nfConntrackMaxHandler.open() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_nfConntrackMaxHandler_read(t *testing.T) {

	var hh nfConntrackMaxHandler
	var nfconntrackCS1 = &containerState{
		stateDataMap: map[string]stateData{
			"/proc/sys/net/netfilter/nf_conntrack_max": {"nf_conntrack_max": "12345"},
		},
	}
	var nfconntrackCS2 = &containerState{
		stateDataMap: map[string]stateData{
			"/proc/sys/net/netfilter/nf_conntrack_max": {"nf_conntrack_max": "123456"},
		},
	}
	var nfconntrackCS3 = &containerState{
		stateDataMap: make(map[string]stateData),
	}
	var nfconntrackCS4 = &containerState{
		stateDataMap: make(map[string]stateData),
	}
	type args struct {
		ionode ioNode
		cs     *containerState
		buf    []byte
		off    int64
	}
	tests := []struct {
		name    string
		h       *nfConntrackMaxHandler
		args    args
		want    int
		wantErr bool
	}{
		// Read current value from (initialized) cs map -- see that file-val doesn't plan any role.
		{"1", &hh, args{newBufferString("no-matter"), nfconntrackCS1, make([]byte, 5), 0}, 5, false},

		// Repeat 1. with higher value.
		{"2", &hh, args{newBufferString("no-matter"), nfconntrackCS2, make([]byte, 6), 0}, 6, false},

		// Read current value from file -- see that cs map is unitilized here.
		{"3", &hh, args{newBufferString("12345"), nfconntrackCS3, make([]byte, 5), 0}, 5, false},

		// Repeat 3. with higher value.
		{"4", &hh, args{newBufferString("123456"), nfconntrackCS4, make([]byte, 6), 0}, 6, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.read(tt.args.ionode, tt.args.cs, tt.args.buf, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("nfConntrackMaxHandler.read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("nfConntrackMaxHandler.read() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_nfConntrackMaxHandler_write(t *testing.T) {

	var hh nfConntrackMaxHandler
	var nfconntrackCS1 = &containerState{
		stateDataMap: map[string]stateData{
			"/proc/sys/net/netfilter/nf_conntrack_max": {"nf_conntrack_max": "12345"},
		},
	}
	var nfconntrackCS2 = &containerState{
		stateDataMap: map[string]stateData{
			"/proc/sys/net/netfilter/nf_conntrack_max": {"nf_conntrack_max": "123456"},
		},
	}
	var nfconntrackCS3 = &containerState{
		stateDataMap: make(map[string]stateData),
	}
	var nfconntrackCS4 = &containerState{
		stateDataMap: make(map[string]stateData),
	}
	type args struct {
		ionode ioNode
		cs     *containerState
		buf    []byte
	}
	tests := []struct {
		name    string
		h       *nfConntrackMaxHandler
		args    args
		want    int
		wantErr bool
	}{
		// Update max with a higher value.
		{"1", &hh, args{newBufferString("65535"), nfconntrackCS1, []byte("65535")}, 5, false},

		// Update max with a lower value -- see that file-val doesn't play any role here.
		{"2", &hh, args{newBufferString("no-matter"), nfconntrackCS2, []byte("80000")}, 5, false},

		// File-val holds unexpected val (wrong format) -- no write() expected and error expected.
		{"3", &hh, args{newBufferString("wrong-val"), nfconntrackCS2, []byte("90000")}, 0, true},

		// Repeat 1. but with a uninitialized cs map.
		{"4", &hh, args{newBufferString("65535"), nfconntrackCS3, []byte("65535")}, 5, false},

		// Repeat 2. but with a uninitialized cs map.
		{"5", &hh, args{newBufferString("65535"), nfconntrackCS4, []byte("80000")}, 5, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.write(tt.args.ionode, tt.args.cs, tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("nfConntrackMaxHandler.write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("nfConntrackMaxHandler.write() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_nfConntrackMaxHandler_fetch(t *testing.T) {
	type args struct {
		ionode ioNode
		cs     *containerState
	}
	tests := []struct {
		name    string
		h       *nfConntrackMaxHandler
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.fetch(tt.args.ionode, tt.args.cs)
			if (err != nil) != tt.wantErr {
				t.Errorf("nfConntrackMaxHandler.fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("nfConntrackMaxHandler.fetch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_nfConntrackMaxHandler_push(t *testing.T) {
	type args struct {
		ionode    ioNode
		cs        *containerState
		newMaxInt int
	}
	tests := []struct {
		name    string
		h       *nfConntrackMaxHandler
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.h.push(tt.args.ionode, tt.args.cs, tt.args.newMaxInt); (err != nil) != tt.wantErr {
				t.Errorf("nfConntrackMaxHandler.push() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_nfConntrackMaxHandler_resource(t *testing.T) {
	tests := []struct {
		name string
		h    *nfConntrackMaxHandler
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.resource(); got != tt.want {
				t.Errorf("nfConntrackMaxHandler.resource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_disableIpv6Handler_open(t *testing.T) {
	type args struct {
		cs    *containerState
		flags fuse.OpenFlags
	}
	tests := []struct {
		name    string
		h       *disableIpv6Handler
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.h.open(tt.args.cs, &tt.args.flags); (err != nil) != tt.wantErr {
				t.Errorf("disableIpv6Handler.open() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_disableIpv6Handler_read(t *testing.T) {
	type args struct {
		node ioNode
		cs   *containerState
		buf  []byte
		off  int64
	}
	tests := []struct {
		name    string
		h       *disableIpv6Handler
		args    args
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.read(tt.args.node, tt.args.cs, tt.args.buf, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("disableIpv6Handler.read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("disableIpv6Handler.read() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_disableIpv6Handler_write(t *testing.T) {
	type args struct {
		node ioNode
		cs   *containerState
		buf  []byte
	}
	tests := []struct {
		name    string
		h       *disableIpv6Handler
		args    args
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.write(tt.args.node, tt.args.cs, tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("disableIpv6Handler.write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("disableIpv6Handler.write() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_disableIpv6Handler_fetch(t *testing.T) {
	type args struct {
		node ioNode
		cs   *containerState
	}
	tests := []struct {
		name    string
		h       *disableIpv6Handler
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.fetch(tt.args.node, tt.args.cs)
			if (err != nil) != tt.wantErr {
				t.Errorf("disableIpv6Handler.fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("disableIpv6Handler.fetch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_disableIpv6Handler_push(t *testing.T) {
	type args struct {
		node   ioNode
		cs     *containerState
		newVal string
	}
	tests := []struct {
		name    string
		h       *disableIpv6Handler
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.h.push(tt.args.node, tt.args.cs, tt.args.newVal); (err != nil) != tt.wantErr {
				t.Errorf("disableIpv6Handler.push() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_disableIpv6Handler_resource(t *testing.T) {
	tests := []struct {
		name string
		h    *disableIpv6Handler
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.resource(); got != tt.want {
				t.Errorf("disableIpv6Handler.resource() = %v, want %v", got, tt.want)
			}
		})
	}
}
