package fuse

import (
	"encoding/json"
	"os"
	"reflect"
	"syscall"

	"bazil.org/fuse"
)

//
// IOerror's purpose is to encapsulate errors to be delivered to FUSE-Bazil
// library, which imposes certain demands on the error types that can be
// handled (i.e. it must satisfy 'errorNumber' interface).
//
// As part of this 'error' implementation, we are also providing an encoding
// specialization method to the (un)marshalling routines involved in 'nsenter'
// processing events. Note that without this specialization, we wouldn't be
// able to encode generic 'error' interface types; which is precisely the
// reason that the 'RcvError' member below is not being exposed to JSON
// marshalling logic.
//
type IOerror struct {
	RcvError error `json:"-"`
	Type     string `json:"type"`
	Code     syscall.Errno `json:"code"`
	Message  string `json:"message"`
}

func (e IOerror) Error() string {
	return e.Message
}

// Method requested by fuse.ErrorNumber interface. By implementing this
// interface, we are allowed to return IOerrors back to our FUSE-lib
// modules without making any modification to Bazil-FUSE code.
func (e IOerror) Errno() fuse.Errno {
	return fuse.Errno(e.Code)
}

// MarshallJSON's interface specialization to allow a customized encoding
// of IOerror struct.
func (e *IOerror) MarshalJSON() ([]byte, error) {

	err := e.RcvError
	if err == nil {
		return nil, nil
	}

	var errcode syscall.Errno

	// Type assertion is needed here to extract the error code corresponding
	// to the different error flavors that may be generated during I/O ops.
	switch v := err.(type) {
	case *os.PathError:
		errcode = v.Err.(syscall.Errno)

	case *os.SyscallError:
		errcode = v.Err.(syscall.Errno)

	case syscall.Errno:
		errcode = v

	default:
		errcode = syscall.EIO
	}

	// Finally, let's populate the fields of NSenterError struct.
	e.Type = reflect.TypeOf(err).String()
	e.Code = errcode
	e.Message = err.Error()

	return json.Marshal(*e)
}