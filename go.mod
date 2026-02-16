module github.com/nestybox/sysbox-fs

go 1.24.0

replace bazil.org/fuse => ./bazil

require (
	bazil.org/fuse v0.0.0-00010101000000-000000000000
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/cyphar/filepath-securejoin v0.6.0
	github.com/docker/docker v28.0.0+incompatible
	github.com/golang/protobuf v1.5.4
	github.com/hashicorp/go-immutable-radix v1.3.0
	github.com/opencontainers/runtime-spec v1.1.1-0.20230823135140-4fec88fd00a4
	github.com/pkg/profile v1.5.0
	github.com/seccomp/libseccomp-golang v0.10.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/afero v1.4.1
	github.com/stretchr/testify v1.11.1
	github.com/urfave/cli v1.22.14
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sys v0.38.0
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.10
	gopkg.in/hlandau/service.v1 v1.0.7
)

require (
	cyphar.com/go-pathrs v0.2.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.1 // indirect
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250825161204-c5933d9347a5 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
