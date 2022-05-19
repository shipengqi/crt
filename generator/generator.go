package generator

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/shipengqi/crt/cert"
	"github.com/shipengqi/crt/key"
)

type Writer interface {
	Write(output string) error
}

type Generator struct {
	keyGen key.Interface
	writer Writer

	ca    *x509.Certificate
	caKey crypto.PrivateKey
}

// New return a new certificate generator.
func New(opts ...Option) *Generator {
	g := &Generator{}
	g.withOptions(opts...)
	return g
}

// Create creates one or more certificates.
func (g *Generator) Create(c *cert.Certificate) error {
	ca := g.ca
	caKey := g.caKey
	privk, err := g.keyGen.Gen()
	if err != nil {
		return err
	}
	pubk := privk.Public()
	encodedKey := g.keyGen.Encode(privk)
	crtObj := c.Gen()
	if c.IsCA() { // set root CA and root key, for generating ca.crt and ca.key
		ca = crtObj
		caKey = privk
	}

	objBytes, err := x509.CreateCertificate(rand.Reader, crtObj, ca, pubk, caKey)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: objBytes,
	}
	return pem.EncodeToMemory(block), encodedKey, nil
}

// withOptions set options for the Generator
func (g *Generator) withOptions(opts ...Option) {
	for _, opt := range opts {
		opt.apply(g)
	}
}
