package sysio

/*
import (
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type PidFile struct {
	ID uint32
	IOnodeFile
}

func (p *PidFile) Id() uint32 {
	return p.ID
}

func (p *PidFile) Inode() (Inode, error) {

	pidnsPath := strings.Join([]string{
		"/proc",
		strconv.FormatUint(uint64(p.ID), 10),
		"ns/pid"}, "/")

	// ionode := &IOnodeFile{
	// 	Path: pidnsPath,
	// }

	// Extract pid-ns info from FS.
	info, err := os.Stat(pidnsPath)
	if err != nil {
		log.Println("No process file found for pid:", p.ID)
		return 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		log.Println("Not a syscall.Stat_t")
		return 0, nil
	}

	return stat.Ino, nil
}

type PidMem struct {
	ID uint64
	//IOnodeMem
}
*/
