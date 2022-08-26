package generator

const (
	DefaultFileMode = 0o400
)

type Writer interface {
	// Write writes certificate and private key to the given filenames
	Write(cert, priv []byte, certname, privname string) error
}
