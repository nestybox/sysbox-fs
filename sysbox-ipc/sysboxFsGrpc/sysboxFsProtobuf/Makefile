# Build dependencies:
#
# 1) Install the protoc compiler that is used to generate gRPC service code.
#
# $ mkdir -p ~/bin/protoc
# $ cd ~/bin/protoc
# $ wget https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protoc-3.6.1-linux-x86_64.zip
# $ unzip protoc-3.6.1-linux-x86_64.zip
# $ sudo cp -r include/* /usr/local/include/
# $ sudo cp bin/protoc /usr/local/bin/
# $ sudo chmod 755 /usr/local/bin/protoc         [ providing execution rights to all users ]
# $ sudo chmod -R 755 /usr/local/include/google  [ providing execution rights to all users ]
#
# temporary folder ~/bin/protoc can be now eliminated if desired:
# $ rm -rf ~/bin/protoc
#
# 2) Install protoc plugin for golang
#
# $ go get -u github.com/golang/protobuf/protoc-gen-go
#
# Make sure that PATH is properly set to cover $GOPATH/bin/:
#
# $ export PATH=$PATH:$GOPATH/bin
#

.PHONY: clean

RUNC_FS_SRC := sysboxFsProtobuf.proto
RUNC_FS_PB := sysboxFsProtobuf.pb.go

.DEFAULT: $(RUNC_FS_PB)

$(RUNC_FS_PB): $(RUNC_FS_SRC)
	GOFLAGS='-buildvcs=false' protoc -I . -I /usr/local/include/ sysboxFsProtobuf.proto --go_out=plugins=grpc:.

clean:
	rm -f $(RUNC_FS_PB)

distclean: clean
