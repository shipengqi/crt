package generator

const (
	DefaultFileMode = 0400
)

type Writer interface {
	Write(raw []byte, output string) error
}
