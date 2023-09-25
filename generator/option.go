package generator

import (
	"crypto"
	"crypto/x509"

	"github.com/shipengqi/crt/key"
)

// Option defines optional parameters for initializing the generator
// structure.
type Option interface {
	apply(g *Generator)
}

// optionFunc wraps a func, so it satisfies the Option interface.
type optionFunc func(*Generator)

func (fn optionFunc) apply(g *Generator) {
	fn(g)
}

// WithKeyGenerator is used to set the private key generator of the Generator.
func WithKeyGenerator(keyG key.Generator) Option {
	return optionFunc(func(g *Generator) {
		g.keyG = keyG
	})
}

// WithCA is used to set the CA pair of the Generator.
func WithCA(ca *x509.Certificate, key crypto.PrivateKey) Option {
	return optionFunc(func(g *Generator) {
		g.ca = ca
		g.caKey = key
	})
}
