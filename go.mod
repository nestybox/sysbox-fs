module github.com/nestybox/sysvisor-fs

go 1.13

require (
	bazil.org/fuse v0.0.0-20180421153158-65cc252bf669
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/nestybox/sysvisor-ipc v0.0.0-20190603003818-483605a8fbcf
	github.com/nestybox/sysvisor-runc v0.1.2
	github.com/spf13/afero v1.2.2
	github.com/stretchr/testify v1.3.0
	github.com/urfave/cli v1.20.0
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	golang.org/x/sys v0.0.0-20190602015325-4c4f7f33c9ed
)

replace github.com/nestybox/sysvisor-runc => ../sysvisor-runc

replace github.com/opencontainers/runc => ./../sysvisor-runc
