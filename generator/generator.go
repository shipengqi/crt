package generator

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/shipengqi/crt"
)

type WriteTo struct {
	Raw []byte
	To  string
}

type Generator struct {
	keyGen crt.Interface
	writer Writer
	ca     *x509.Certificate
	caKey  crypto.PrivateKey
}

// New return a new certificate generator.
func New(opts ...Option) *Generator {
	g := &Generator{
		writer: NewFileWriter(),
		keyGen: crt.NewRsaKey(crt.RecommendedKeyLength),
	}
	g.withOptions(opts...)
	return g
}

// SetCA is used to set the CA pair of the Generator.
func (g *Generator) SetCA(ca *x509.Certificate, key crypto.PrivateKey) {
	g.ca = ca
	g.caKey = key
}

// Create creates a new X.509 v3 certificate and private key based on a template.
func (g *Generator) Create(c *crt.Certificate) ([]byte, []byte, error) {
	ca := g.ca
	caKey := g.caKey
	signer, err := g.keyGen.Gen()
	if err != nil {
		return nil, nil, err
	}
	pub := signer.Public()
	encoded := g.keyGen.Encode(signer)
	x509crt := c.Gen()
	if c.IsCA() { // set CA and ca key, for generating ca.crt and ca.key
		ca = x509crt
		caKey = signer
	} else if ca == nil || caKey == nil {
		return nil, nil, errors.New("x509: certificate or private key is not provided")
	}

	v3crt, err := x509.CreateCertificate(rand.Reader, x509crt, ca, pub, caKey)
	if err != nil {
		return nil, nil, err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: v3crt,
	}
	return pem.EncodeToMemory(block), encoded, nil
}

// Write set options for the Generator
func (g *Generator) Write(tos []WriteTo) error {
	for _, v := range tos {
		err := g.writer.Write(v.Raw, v.To)
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateAndWrite creates a new X.509 v3 certificate and private key, then execute the Writer.Write.
func (g *Generator) CreateAndWrite(c *crt.Certificate, certOutput, keyOutput string) error {
	certRaw, keyRaw, err := g.Create(c)
	if err != nil {
		return err
	}
	return g.Write([]WriteTo{
		{Raw: certRaw, To: certOutput},
		{Raw: keyRaw, To: keyOutput},
	})
}

// withOptions set options for the Generator
func (g *Generator) withOptions(opts ...Option) {
	for _, opt := range opts {
		opt.apply(g)
	}
}
