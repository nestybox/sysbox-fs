#
# sysvisor-fs Makefile
#
# Note: targets must execute from the $SYSFS_GO_DIR

.PHONY: clean sysvisor-fs-debug sysvisor-fs-static

PROJECT := github.com/nestybox/sysvisor
SYSFS_GO_DIR := $(GOPATH)/src/$(PROJECT)/sysvisor-fs

SYSFS_SRC := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')
SYSFS_GRPC_DIR := ../sysvisor-ipc/sysvisorFsGrpc
SYSFS_GRPC_SRC := $(shell find $(SYSFS_GRPC_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

sysvisor-fs: $(SYSFS_SRC) $(SYSFS_GRPC_SRC)
	go build -o sysvisor-fs ./cmd/sysvisor-fs

sysvisor-fs-debug: $(SYSFS_SRC) $(SYSFS_GRPC_SRC)
	go build -gcflags="all=-N -l" -o sysvisor-fs ./cmd/sysvisor-fs

sysvisor-fs-static: $(SYSFS_SRC) $(SYSFS_GRPC_SRC)
	CGO_ENABLED=1 go build -tags "netgo osusergo static_build" -installsuffix netgo -ldflags "-w -extldflags -static" -o sysvisor-fs ./cmd/sysvisor-fs

clean:
	rm -f sysvisor-fs
