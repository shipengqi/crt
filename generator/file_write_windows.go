package generator

import (
	"os"
)

// Write implements Writer interface.
func (w *FileWriter) Write(cert, pkey []byte, certname, privname string) error {
	err := os.WriteFile(certname, cert, w.fmode)
	if err != nil {
		return err
	}
	return os.WriteFile(privname, pkey, w.fmode)
}
