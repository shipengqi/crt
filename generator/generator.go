package generator

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/shipengqi/crt"
	"github.com/shipengqi/crt/key"
)

// Generator is the main structure of a generator.
type Generator struct {
	keyG   key.Generator
	writer Writer
	ca     *x509.Certificate
	caKey  crypto.PrivateKey
}

// New return a new certificate generator.
func New(opts ...Option) *Generator {
	g := &Generator{
		writer: NewFileWriter(),
		keyG:   key.NewRsaKey(key.RecommendedKeyLength),
	}
	g.withOptions(opts...)
	return g
}

// CA returns the CA pair of the Generator.
func (g *Generator) CA() (ca *x509.Certificate, priv crypto.PrivateKey) {
	return g.ca, g.caKey
}

// SetCA is used to set the CA pair of the Generator.
func (g *Generator) SetCA(ca *x509.Certificate, priv crypto.PrivateKey) {
	g.ca = ca
	g.caKey = priv
}

// SetWriter is used to set the Writer of the Generator.
func (g *Generator) SetWriter(w Writer) {
	g.writer = w
}

// SetKeyGenerator is used to set the key.Generator of the Generator.
func (g *Generator) SetKeyGenerator(gen key.Generator) {
	g.keyG = gen
}

// Create creates a new X.509 v3 certificate and private key based on a template.
func (g *Generator) Create(c *crt.Certificate) (cert []byte, priv []byte, err error) {
	ca := g.ca
	caKey := g.caKey
	signer, err := g.keyG.Gen()
	if err != nil {
		return nil, nil, err
	}
	pub := signer.Public()
	priv = g.keyG.Encode(signer)
	x509crt := c.Gen()
	if c.IsCA() { // set CA and ca key, for generating ca.crt and ca.key
		ca = x509crt
		caKey = signer
	} else if ca == nil || caKey == nil {
		return nil, nil, errors.New("x509: CA certificate or private key is not provided")
	}

	v3crt, err := x509.CreateCertificate(rand.Reader, x509crt, ca, pub, caKey)
	if err != nil {
		return nil, nil, err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: v3crt,
	}
	cert = pem.EncodeToMemory(block)
	return cert, priv, nil
}

// Write set options for the Generator.
func (g *Generator) Write(cert, priv []byte, certname, privname string) error {
	return g.writer.Write(cert, priv, certname, privname)
}

// CreateAndWrite creates a new X.509 v3 certificate and private key, then execute the Writer.Write.
func (g *Generator) CreateAndWrite(c *crt.Certificate, certname, privname string) error {
	cert, priv, err := g.Create(c)
	if err != nil {
		return err
	}
	return g.Write(cert, priv, certname, privname)
}

// withOptions set options for the Generator.
func (g *Generator) withOptions(opts ...Option) {
	for _, opt := range opts {
		opt.apply(g)
	}
}
