package main

import (
	"bytes"
	"io"
	"log"
	"os"
)

//
// ioNode interface serves as an abstract-class to represent all I/O resources
// with whom sysvisor-fs operates. All I/O transactions will be carried out
// through the methods exposed by this interface and its derived sub-classes.
// There are two specializations of this interface at the moment:
//
// 1. ioNodeFile: Basically, a wrapper over os.File type to allow interactions
//    with the host FS. To be utilized in production scenarios.
//
// 2. ioNodeBuffer: An enhanced byte-buffer class wrapper. To be utilized
//    during UT efforts.
//
type ioNode interface {
	io.Reader
	io.ReaderAt
	io.Writer
	io.Closer
}

// Common constructor for all ioNode specializations.
func newIoNode(path string, flags int, attr os.FileMode) ioNode {

	var (
		newNode ioNode
		err     error
	)

	if unitTesting {
		newNode = &ioNodeBuffer{}
	} else {
		newNode, err = os.OpenFile(path, int(flags), attr)
		if err != nil {
			log.Print("Open ERR:", err)
			return nil
		}
	}

	return newNode
}

// ioNodeFile specialization. Utilized in production scenarios.
type ioNodeFile struct {
	reader   io.Reader
	readerat io.ReaderAt
	writer   io.Writer
	closer   io.Closer
}

// Regular read() instruction to obtain state from host FS.
func (i *ioNodeFile) Read(p []byte) (int, error) {

	n, err := i.reader.Read(p)
	if err != nil && err != io.EOF {
		log.Println("Read ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular readAt() instruction to obtain state from host FS.
func (i *ioNodeFile) ReadAt(p []byte, offset int64) (int, error) {

	n, err := i.readerat.ReadAt(p, offset)
	if err != nil && err != io.EOF {
		log.Println("Read ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular write() instruction to inject state into host FS.
func (i *ioNodeFile) Write(p []byte) (n int, err error) {

	n, err = i.writer.Write(p)
	if err != nil {
		log.Println("Write ERR:", err)
		return 0, err
	}

	return n, nil
}

// Regular close() instruction for host FS.
func (i *ioNodeFile) Close() error {
	return i.closer.Close()
}

//
// ioNodeBuffer specialization. Enhances the regular bytes.Buffer class by
// providing ReadAt() and Close() methods in order to satisfy ioNode interface.
// Utilized in UT scenarios.
//
type ioNodeBuffer struct {
	bytes.Buffer
}

func newIoNodeBuffer(buf []byte) *ioNodeBuffer {
	var newnode ioNodeBuffer

	newnode.Buffer = *(bytes.NewBuffer(buf))

	return &newnode
}

func newBufferString(s string) *ioNodeBuffer {
	var newnode ioNodeBuffer

	newnode.Buffer = *(bytes.NewBufferString(s))

	return &newnode
}

func (i *ioNodeBuffer) ReadAt(p []byte, offset int64) (int, error) {
	// TODO: Implement a proper readAt() method for this class.
	return i.Buffer.Read(p)
}

func (i *ioNodeBuffer) Close() error {
	i.Buffer.Reset()
	return nil
}

func (i *ioNodeBuffer) WriteString(s string) int {
	n, _ := i.Buffer.WriteString(s)

	return n
}
