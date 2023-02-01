module github.com/nestybox/sysbox-fs

go 1.13

require (
	bazil.org/fuse v0.0.0-20180421153158-65cc252bf669
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.0
	github.com/hashicorp/go-uuid v1.0.1 // indirect
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/nestybox/sysbox-ipc v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/capability v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/formatter v0.0.0-20210709231355-1ea69f2f6dbb
	github.com/nestybox/sysbox-libs/libseccomp-golang v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/linuxUtils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/pidfd v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-libs/utils v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-runc v0.0.0-00010101000000-000000000000
	github.com/pkg/profile v1.5.0
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/afero v1.4.1
	github.com/stretchr/objx v0.3.0 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli v1.22.5
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8
	google.golang.org/grpc v1.34.1
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/hlandau/service.v1 v1.0.7
)

replace (
	github.com/nestybox/sysbox-ipc => ../sysbox-ipc
	github.com/nestybox/sysbox-runc => ../sysbox-runc
	github.com/nestybox/sysbox-libs/utils => ../sysbox-libs/utils
	github.com/nestybox/sysbox-libs/linuxUtils => ../sysbox-libs/linuxUtils
	github.com/nestybox/sysbox-libs/dockerUtils => ../sysbox-libs/dockerUtils
	github.com/nestybox/sysbox-libs/libseccomp-golang => ../sysbox-libs/libseccomp-golang
	github.com/nestybox/sysbox-libs/pidmonitor => ../sysbox-libs/pidmonitor
	github.com/nestybox/sysbox-libs/pidfd => ../sysbox-libs/pidfd
	github.com/nestybox/sysbox-libs/capability => ../sysbox-libs/capability
	github.com/nestybox/sysbox-libs/formatter => ../sysbox-libs/formatter
	github.com/nestybox/sysbox-libs/idShiftUtils => ../sysbox-libs/idShiftUtils
	github.com/nestybox/sysbox-libs/overlayUtils => ../sysbox-libs/overlayUtils
	github.com/nestybox/sysbox-libs/mount => ../sysbox-libs/mount
	github.com/nestybox/sysbox-libs/shiftfs => ../sysbox-libs/shiftfs
	github.com/nestybox/sysbox-libs/idMap => ../sysbox-libs/idMap
	github.com/opencontainers/runc => ./../sysbox-runc
	bazil.org/fuse => ./bazil
	github.com/godbus/dbus => github.com/godbus/dbus/v5 v5.0.3
)