package generator

// Writer is the interface that wraps the basic Write method.
type Writer interface {
	// Write writes certificate and private key
	Write(cert, prik []byte) error
}

// Closer is the interface that wraps the basic Close method.
type Closer interface {
	Close() error
}

// WriteCloser is the interface that groups the basic Write and Close methods.
type WriteCloser interface {
	Writer
	Closer
}
