#
# sysbox-fs Makefile
#
# Note: targets must execute from the $SYSFS_DIR

.PHONY: clean sysbox-fs-debug sysbox-fs-static lint list-packages

GO := go

SYSFS_DIR := $(CURDIR)
SYSFS_SRC := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')

SYSIPC_DIR := ../sysbox-ipc
SYSIPC_SRC := $(shell find $(SYSIPC_DIR) 2>&1 | grep -E '.*\.(c|h|go|proto)$$')

LIBSECCOMP_DIR := ../lib/seccomp-golang
LIBSECCOMP_SRC := $(shell find $(LIBSECCOMP_DIR) 2>&1 | grep -E '.*\.(go)')

LIBPIDMON_DIR := ../sysbox-libs/pidmonitor
LIBSPIDMON_SRC := $(shell find $(LIBPIDMON_DIR) 2>&1 | grep -E '.*\.(go)')

NSENTER_DIR := ../sysbox-runc/libcontainer/nsenter
NSENTER_SRC := $(shell find $(NSENTER_DIR) 2>&1 | grep -E '.*\.(c|h|go)')

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")
BUILT_AT := $(shell date)
BUILT_BY := $(shell git config user.name)

LDFLAGS := '-X main.version=${VERSION} -X main.commitId=$(COMMIT) \
		-X "main.builtAt=$(BUILT_AT)" -X "main.builtBy=$(BUILT_BY)"'

sysbox-fs: $(SYSFS_SRC) $(SYSIPC_SRC) $(LIBSECCOMP_SRC) $(LIBPIDMON_SRC) $(NSENTER_SRC)
	$(GO) build -ldflags ${LDFLAGS}	-o sysbox-fs ./cmd/sysbox-fs

sysbox-fs-debug: $(SYSFS_SRC) $(SYSIPC_SRC) $(LIBSECCOMP_SRC) $(LIBPIDMON_SRC) $(NSENTER_SRC)
	$(GO) build -gcflags="all=-N -l" -ldflags ${LDFLAGS} -o sysbox-fs ./cmd/sysbox-fs

sysbox-fs-static: $(SYSFS_SRC) $(SYSIPC_SRC) $(LIBSECCOMP_SRC) $(LIBPIDMON_SRC) $(NSENTER_SRC)
	CGO_ENABLED=1 $(GO) build -tags "netgo osusergo static_build" \
		-installsuffix netgo -ldflags "-w -extldflags -static" -ldflags ${LDFLAGS} \
		-o sysbox-fs ./cmd/sysbox-fs

lint:
	$(GO) vet $(allpackages)
	$(GO) fmt $(allpackages)

listpackages:
	@echo $(allpackages)

clean:
	rm -f sysbox-fs

# memoize allpackages, so that it's executed only once and only if used
_allpackages = $(shell $(GO) list ./... | grep -v vendor)
allpackages = $(if $(__allpackages),,$(eval __allpackages := $$(_allpackages)))$(__allpackages)
