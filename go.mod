module github.com/nestybox/sysbox-fs

go 1.13

require (
	bazil.org/fuse v0.0.0-20180421153158-65cc252bf669
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/nestybox/sysbox-ipc v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-runc v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox/lib/pathres v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox/lib/pidmonitor v0.0.0-00010101000000-000000000000
	github.com/pkg/profile v1.4.0
	github.com/seccomp/libseccomp-golang v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero v1.2.2
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.5.1
	github.com/urfave/cli v1.20.0
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/sys v0.0.0-20191224085550-c709ea063b76
	gopkg.in/hlandau/service.v1 v1.0.7
)

replace github.com/nestybox/sysbox-ipc => ../sysbox-ipc

replace github.com/nestybox/sysbox-runc => ../sysbox-runc

replace github.com/opencontainers/runc => ./../sysbox-runc

replace bazil.org/fuse => ./bazil

replace github.com/seccomp/libseccomp-golang => ../lib/seccomp-golang

replace github.com/nestybox/sysbox/lib/pathres => ../lib/pathres

replace github.com/nestybox/sysbox/lib/pidmonitor => ../lib/pidmonitor
