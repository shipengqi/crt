package generator

import (
	"os"
)

// FileWriter implements Writer interface.
type FileWriter struct {
	uid   int
	gid   int
	fmode os.FileMode
}

// NewFileWriter creates a new FileWriter with default options.
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
