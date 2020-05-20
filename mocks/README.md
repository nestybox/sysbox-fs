# Mocks generation

To generate or update code mocks in this folder simply follow these steps ...

1) Download required binaries / libs if not already done:

```
rmolina@dev-vm1:~/wsp/05-07-2020/sysbox/sysbox-fs$ go get github.com/stretchr/testify
rmolina@dev-vm1:~/wsp/05-07-2020/sysbox/sysbox-fs$ go get github.com/vektra/mockery/.../
```

2) Execute 'mock' binary by pointing to the interface that you want to mock and
the path where this one is located. In sysbox-fs' case, all interfaces are defined
within the "domain" folder:

```
rmolina@dev-vm1:~/wsp/05-07-2020/sysbox/sysbox-fs$ mockery -name=FuseServerIface -dir=domain
Generating mock for: FuseServerIface in file: mocks/FuseServerIface.go
```