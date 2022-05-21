package generator

import (
	"io/ioutil"
	"os"
	"syscall"
)

type FileWriter struct {
	uid   int
	gid   int
	fmode os.FileMode
}

func NewFileWriter() *FileWriter {
	return &FileWriter{
		uid:   os.Getuid(),
		gid:   os.Getgid(),
		fmode: os.FileMode(DefaultFileMode),
	}
}

// SetUid set uid of the output file.
func (w *FileWriter) SetUid(uid int) {
	w.uid = uid
}

// SetGid set gid of the output file.
func (w *FileWriter) SetGid(gid int) {
	w.gid = gid
}

// SetFileMode set os.FileMode of the output file.
func (w *FileWriter) SetFileMode(mode int) {
	w.fmode = os.FileMode(mode)
}

// Write set options for the Generator
func (w *FileWriter) Write(raw []byte, output string) error {
	err := ioutil.WriteFile(output, raw, w.fmode)
	if err != nil {
		return err
	}
	err = syscall.Chown(output, w.uid, w.gid)
	if err != nil {
		return err
	}

	return nil
}
