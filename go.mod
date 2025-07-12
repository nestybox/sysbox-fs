module github.com/nestybox/sysbox-fs

go 1.22

toolchain go1.22.6

require (
	bazil.org/fuse v0.0.0-00010101000000-000000000000
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/hashicorp/go-immutable-radix v1.3.0
	github.com/nestybox/sysbox-ipc v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/capability v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/formatter v0.0.0-20210709231355-1ea69f2f6dbb
	github.com/nestybox/sysbox-libs/linuxUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/pidfd v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/utils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-runc v0.0.0-00010101000000-000000000000
	github.com/pkg/profile v1.5.0
	github.com/seccomp/libseccomp-golang v0.10.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/afero v1.4.1
	github.com/stretchr/testify v1.8.4
	github.com/urfave/cli v1.22.14
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sys v0.26.0
	google.golang.org/grpc v1.64.0
	gopkg.in/hlandau/service.v1 v1.0.7
)

require (
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/checkpoint-restore/go-criu/v4 v4.1.0 // indirect
	github.com/cilium/ebpf v0.3.0 // indirect
	github.com/containerd/console v1.0.1 // indirect
	github.com/coreos/go-systemd/v22 v22.1.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/cyphar/filepath-securejoin v0.2.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/deckarep/golang-set v1.8.0 // indirect
	github.com/deckarep/golang-set/v2 v2.3.1 // indirect
	github.com/docker/docker v26.0.0+incompatible // indirect
	github.com/godbus/dbus/v5 v5.0.3 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/go-uuid v1.0.1 // indirect
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/joshlf/go-acl v0.0.0-20200411065538-eae00ae38531 // indirect
	github.com/karrick/godirwalk v1.16.1 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/moby/sys/mountinfo v0.4.0 // indirect
	github.com/mrunalp/fileutils v0.5.0 // indirect
	github.com/nestybox/sysbox-libs/idMap v0.0.0-00010101000000-000000000000 // indirect
	github.com/nestybox/sysbox-libs/idShiftUtils v0.0.0-00010101000000-000000000000 // indirect
	github.com/nestybox/sysbox-libs/mount v0.0.0-20240602025437-33cbdf5a9e98 // indirect
	github.com/nestybox/sysbox-libs/overlayUtils v0.0.0-00010101000000-000000000000 // indirect
	github.com/nestybox/sysbox-libs/shiftfs v0.0.0-00010101000000-000000000000 // indirect
	github.com/opencontainers/runc v1.1.4 // indirect
	github.com/opencontainers/runtime-spec v1.1.1-0.20230823135140-4fec88fd00a4 // indirect
	github.com/opencontainers/selinux v1.8.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	github.com/willf/bitset v1.1.11 // indirect
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240513163218-0867130af1f8 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	bazil.org/fuse => ./bazil
	github.com/godbus/dbus => github.com/godbus/dbus/v5 v5.0.3
	github.com/nestybox/sysbox-ipc => ../sysbox-ipc
	github.com/nestybox/sysbox-libs/capability => ../sysbox-libs/capability
	github.com/nestybox/sysbox-libs/dockerUtils => ../sysbox-libs/dockerUtils
	github.com/nestybox/sysbox-libs/formatter => ../sysbox-libs/formatter
	github.com/nestybox/sysbox-libs/idMap => ../sysbox-libs/idMap
	github.com/nestybox/sysbox-libs/idShiftUtils => ../sysbox-libs/idShiftUtils
	github.com/nestybox/sysbox-libs/linuxUtils => ../sysbox-libs/linuxUtils
	github.com/nestybox/sysbox-libs/mount => ../sysbox-libs/mount
	github.com/nestybox/sysbox-libs/overlayUtils => ../sysbox-libs/overlayUtils
	github.com/nestybox/sysbox-libs/pidfd => ../sysbox-libs/pidfd
	github.com/nestybox/sysbox-libs/pidmonitor => ../sysbox-libs/pidmonitor
	github.com/nestybox/sysbox-libs/shiftfs => ../sysbox-libs/shiftfs
	github.com/nestybox/sysbox-libs/utils => ../sysbox-libs/utils
	github.com/nestybox/sysbox-runc => ../sysbox-runc
	github.com/opencontainers/runc => ./../sysbox-runc
)
