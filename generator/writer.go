package generator

const (
	DefaultFileMode = 0o400
)

type Writer interface {
	// Write writes bytes to the given output
	Write(raw []byte, output string) error
}
