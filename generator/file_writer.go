package generator

import (
	"os"
)

var _ WriteCloser = &FileWriter{}

// FileWriter implements Writer interface.
type FileWriter struct {
	certf *os.File
	prikf *os.File
}

// NewFileWriter creates a new FileWriter with certificate *os.File and private key *os.File.
func NewFileWriter(certfile, prikfile *os.File) *FileWriter {
	return &FileWriter{
		certf: certfile,
		prikf: prikfile,
	}
}

// NewFileWriterFromPaths creates a new FileWriter with the given certificate and private key paths.
func NewFileWriterFromPaths(certfile, prikfile string) (*FileWriter, error) {
	certf, err := os.Create(certfile)
	if err != nil {
		return nil, err
	}
	prikf, err := os.Create(prikfile)
	if err != nil {
		return nil, err
	}
	return &FileWriter{
		certf: certf,
		prikf: prikf,
	}, nil
}

// Write implements Writer interface.
func (fw *FileWriter) Write(cert, prik []byte) error {
	_, err := fw.certf.Write(cert)
	if err != nil {
		return err
	}
	_, err = fw.prikf.Write(prik)
	if err != nil {
		return err
	}
	return nil
}

// Close implements Closer interface.
func (fw *FileWriter) Close() error {
	err := fw.certf.Close()
	if err != nil {
		return err
	}
	return fw.prikf.Close()
}
