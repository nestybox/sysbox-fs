package main

import (
	"context"
	"log"

	"bazil.org/fuse"
)

//
// Dir struct serves as a FUSE-friendly abstraction to represent file-directories
// present in the host FS.
//
type Dir struct {
	// TODO: Populate needed fields. Think about must-have requirements.
	path string
}

//
// Attr FS instruction
//
func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {

	log.Println("Requested Attr for directory", d.path)

	// TODO: "a" should be modified before returning.

	return nil
}
