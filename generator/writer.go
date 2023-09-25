package generator

const (
	DefaultFileMode = 0o400
)

type Writer interface {
	// Write writes certificate and private key
	Write(cert, priv []byte) error
}
