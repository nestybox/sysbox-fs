package sysio

/*
//
// ioNodeBuffer specialization. Enhances the regular bytes.Buffer class by
// providing ReadAt() and Close() methods in order to satisfy ioNode interface.
// Utilized in UT scenarios.
//

type ioConfigBuffer struct {
	data []byte
}

type ioNodeBuffer struct {
	bytes.Buffer
}

func newNodeBuffer(cfgIntf IOconfig) IOnode {

	config := cfgIntf.(*ioConfigBuffer)
	if config == nil {
		return nil
	}

	newNode := ioNodeBuffer{
		Buffer: *(bytes.NewBuffer(config.data)),
	}

	return &newNode
}

func newNodeBufferString(s string) *ioNodeBuffer {
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
*/
