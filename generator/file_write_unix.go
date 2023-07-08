//go:build linux || darwin

package generator

import (
	"os"
	"syscall"
)

// Write implements Writer interface.
func (w *FileWriter) Write(cert, priv []byte, certname, privname string) error {
	err := w.writeAndChown(cert, certname)
	if err != nil {
		return err
	}
	return w.writeAndChown(priv, privname)
}

func (w *FileWriter) writeAndChown(raw []byte, output string) error {
	err := os.WriteFile(output, raw, w.fmode)
	if err != nil {
		return err
	}
	err = syscall.Chown(output, w.uid, w.gid)
	if err != nil {
		return err
	}

	return nil
}
