module github.com/nestybox/sysbox-fs

go 1.13

require (
	bazil.org/fuse v0.0.0-20180421153158-65cc252bf669
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/nestybox/sysbox-ipc v0.0.0-00010101000000-000000000000
	github.com/nestybox/sysbox-runc v0.1.2
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero v1.2.2
	github.com/stretchr/testify v1.3.0
	github.com/urfave/cli v1.20.0
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f // indirect
	golang.org/x/sys v0.0.0-20190614160838-b47fdc937951
)

replace github.com/nestybox/sysbox-ipc => ../sysbox-ipc

replace github.com/nestybox/sysbox-runc => ../sysbox-runc

replace github.com/opencontainers/runc => ./../sysbox-runc

replace bazil.org/fuse => ./bazil
