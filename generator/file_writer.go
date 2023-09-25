package generator

import (
	"os"
)

// FileWriter implements Writer interface.
type FileWriter struct {
	certf *os.File
	prikf *os.File
}

// NewFileWriter creates a new FileWriter with default options.
func NewFileWriter(certfile, prikfile *os.File) *FileWriter {
	return &FileWriter{
		certf: certfile,
		prikf: prikfile,
	}
}

// Write implements Writer interface.
func (w *FileWriter) Write(cert, prik []byte) error {
	_, err := w.certf.Write(cert)
	if err != nil {
		return err
	}
	_, err = w.prikf.Write(prik)
	if err != nil {
		return err
	}
	return nil
}
