package generator

import (
	"io/ioutil"
	"syscall"
)

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
