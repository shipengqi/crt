package generator

import (
	"io/ioutil"
)

// Write implements Writer interface.
func (w *FileWriter) Write(cert, priv []byte, certname, privname string) error {
	err := ioutil.WriteFile(certname, cert, w.fmode)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(privname, priv, w.fmode)
}
