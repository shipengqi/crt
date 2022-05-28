package generator

import (
	"io/ioutil"
)

// Write set options for the Generator
func (w *FileWriter) Write(raw []byte, output string) error {
	err := ioutil.WriteFile(output, raw, w.fmode)
	if err != nil {
		return err
	}
	return nil
}
