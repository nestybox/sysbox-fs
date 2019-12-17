#
# sysbox-fs Makefile
#
# Note: targets must execute from the $SYSFS_DIR

.PHONY: clean sysbox-fs-debug sysbox-fs-static

GO := go

SYSFS_DIR := $(CURDIR)
SYSFS_SRC := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')

SYSFS_GRPC_DIR := ../sysbox-ipc/sysboxFsGrpc
SYSFS_GRPC_SRC := $(shell find $(SYSFS_GRPC_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

LIBSECCOMP_DIR := ../lib/seccomp-golang
LIBSECCOMP_SRC := $(shell find $(LIBSECCOMP_DIR) 2>&1 | grep -E '.*\.(go)')

LDFLAGS := '-X main.version=${VERSION} -X main.commitId=${COMMIT_ID} \
			-X "main.builtAt=${BUILT_AT}" -X main.builtBy=${BUILT_BY}'

sysbox-fs: $(SYSFS_SRC) $(SYSFS_GRPC_SRC) $(LIBSECCOMP_SRC)
	$(GO) build -ldflags ${LDFLAGS}	-o sysbox-fs ./cmd/sysbox-fs

sysbox-fs-debug: $(SYSFS_SRC) $(SYSFS_GRPC_SRC) $(LIBSECCOMP_SRC)
	$(GO) build -gcflags="all=-N -l" -o sysbox-fs ./cmd/sysbox-fs

sysbox-fs-static: $(SYSFS_SRC) $(SYSFS_GRPC_SRC) $(LIBSECCOMP_SRC)
	CGO_ENABLED=1 $(GO) build -tags "netgo osusergo static_build" \
		-installsuffix netgo -ldflags "-w -extldflags -static" \
		-o sysbox-fs ./cmd/sysbox-fs

clean:
	rm -f sysbox-fs
