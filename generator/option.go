package generator

import (
	"crypto"
	"crypto/x509"

	"github.com/shipengqi/crt"
)

type Option interface {
	apply(g *Generator)
}

// optionFunc wraps a func, so it satisfies the Option interface.
type optionFunc func(*Generator)

func (fn optionFunc) apply(g *Generator) {
	fn(g)
}

// WithWriter is used to set the Writer of the Generator.
func WithWriter(writer Writer) Option {
	return optionFunc(func(g *Generator) {
		g.writer = writer
	})
}

// WithKeyType is used to set the private key generator of the Generator.
func WithKeyType(t crt.Type) Option {
	var keyG crt.Interface
	if t == crt.EcdsaKeyType {
		keyG = crt.NewEcdsaKey()
	} else {
		keyG = crt.NewRsaKey(crt.RecommendedKeyLength)
	}
	return optionFunc(func(g *Generator) {
		g.keyGen = keyG
	})
}

// WithCA is used to set the CA pair of the Generator.
func WithCA(ca *x509.Certificate, key crypto.PrivateKey) Option {
	return optionFunc(func(g *Generator) {
		g.ca = ca
		g.caKey = key
	})
}
