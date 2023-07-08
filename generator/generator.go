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

const (
	DefaultKeyCipher = x509.PEMCipherAES256
)

// WriteOptions defines options for Writer.Write.
type WriteOptions struct {
	W Writer
}

// CreateOptions defines options for Generator.Create.
// KeyPassphrase can be nil, otherwise use it to encrypt the private key.
type CreateOptions struct {
	G             key.Generator
	KeyPassphrase []byte
	KeyCipher     x509.PEMCipher
}

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

// Create creates a new X.509 v3 certificate and private key based on a template.
func (g *Generator) Create(c *crt.Certificate) (cert []byte, priv []byte, err error) {
	return g.create(c, CreateOptions{})
}

// CreateWithOptions creates a new X.509 v3 certificate and private key based on a template with the given CreateOptions.
func (g *Generator) CreateWithOptions(c *crt.Certificate, opt CreateOptions) (cert []byte, priv []byte, err error) {
	if opt.KeyCipher < 1 {
		opt.KeyCipher = DefaultKeyCipher
	}
	return g.create(c, opt)
}

// Write writes the certificate and key files by the Writer.
func (g *Generator) Write(cert, priv []byte, certname, privname string) error {
	return g.write(cert, priv, certname, privname, WriteOptions{})
}

// WriteWithOptions writes the certificate and key files by the Writer with the given WriteOptions.
func (g *Generator) WriteWithOptions(cert, priv []byte, certname, privname string, opt WriteOptions) error {
	return g.write(cert, priv, certname, privname, opt)
}

// CreateAndWrite creates a new X.509 v3 certificate and private key, then execute the Writer.Write.
func (g *Generator) CreateAndWrite(c *crt.Certificate, certname, privname string) error {
	cert, priv, err := g.Create(c)
	if err != nil {
		return err
	}
	return g.Write(cert, priv, certname, privname)
}

func (g *Generator) create(c *crt.Certificate, opt CreateOptions) (cert []byte, priv []byte, err error) {
	keyG := g.keyG
	if opt.G != nil {
		keyG = opt.G
	}

	ca := g.ca
	caKey := g.caKey
	signer, err := keyG.Gen()
	if err != nil {
		return nil, nil, err
	}
	pub := signer.Public()

	b, err := keyG.Marshal(signer)
	if err != nil {
		return nil, nil, err
	}
	if len(opt.KeyPassphrase) > 0 {
		//nolint:staticcheck
		eb, err := x509.EncryptPEMBlock(rand.Reader, keyG.BlockType(), b, opt.KeyPassphrase, opt.KeyCipher)
		if err != nil {
			return nil, nil, err
		}
		priv = pem.EncodeToMemory(eb)
	} else {
		priv = keyG.Encode(b)
	}
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

func (g *Generator) write(cert, priv []byte, certname, privname string, opt WriteOptions) error {
	w := g.writer
	if opt.W != nil {
		w = opt.W
	}
	return w.Write(cert, priv, certname, privname)
}

// withOptions set options for the Generator.
func (g *Generator) withOptions(opts ...Option) {
	for _, opt := range opts {
		opt.apply(g)
	}
}
