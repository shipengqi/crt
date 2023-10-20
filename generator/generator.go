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

// CreateOptions defines options for Generator.Create.
// UseAsCA if true, the given crt.Certificate will be used as the CA
// certificate for the Generator. If the crt.Certificate is not CA type,
// UseAsCA will be ignored.
// AppendCA if true, the CA certificate of the Generator will append to the result.
type CreateOptions struct {
	G        key.Generator
	KeyOpts  *key.MarshalOptions
	UseAsCA  bool
	AppendCA bool
}

// Generator is the main structure of a generator.
type Generator struct {
	keyG  key.Generator
	ca    *x509.Certificate
	caKey crypto.PrivateKey
}

// New return a new certificate generator.
func New(opts ...Option) *Generator {
	g := &Generator{
		keyG: key.NewRsaKey(key.RecommendedKeyLength),
	}
	g.withOptions(opts...)

	return g
}

// CA returns the CA pair of the Generator.
func (g *Generator) CA() (ca *x509.Certificate, pkey crypto.PrivateKey) {
	return g.ca, g.caKey
}

// SetCA is used to set the CA pair of the Generator.
func (g *Generator) SetCA(ca *x509.Certificate, pkey crypto.PrivateKey) {
	g.ca = ca
	g.caKey = pkey
}

// Create creates a new X.509 v3 certificate and private key based on a template.
func (g *Generator) Create(c *crt.Certificate) (cert []byte, pkey []byte, err error) {
	return g.create(c, CreateOptions{})
}

// CreateWithOptions creates a new X.509 v3 certificate and private key based on a template with the given CreateOptions.
func (g *Generator) CreateWithOptions(c *crt.Certificate, opts CreateOptions) (cert []byte, pkey []byte, err error) {
	return g.create(c, opts)
}

// CreateAndWrite creates a new X.509 v3 certificate and private key, then execute the Writer.Write.
func (g *Generator) CreateAndWrite(w WriteCloser, c *crt.Certificate) error {
	cert, pkey, err := g.Create(c)
	if err != nil {
		return err
	}
	defer func() { _ = w.Close() }()
	return w.Write(cert, pkey)
}

func (g *Generator) create(c *crt.Certificate, opts CreateOptions) (cert []byte, pkey []byte, err error) {
	keyG := g.keyG
	if opts.G != nil {
		keyG = opts.G
	}

	ca := g.ca
	caKey := g.caKey
	signer, err := keyG.Gen()
	if err != nil {
		return nil, nil, err
	}
	pub := signer.Public()

	pkey, err = keyG.Marshal(signer, opts.KeyOpts)
	if err != nil {
		return nil, nil, err
	}
	x509crt := c.Gen()
	if c.IsCA() { // if the given cert is CA type, skip checking CA certificate and private key
		ca = x509crt
		caKey = signer
		// set current CA and CA key for the generator
		if opts.UseAsCA {
			g.ca = ca
			g.caKey = caKey
		}
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
	if opts.AppendCA && g.ca != nil && g.ca != ca {
		capem := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: g.ca.Raw,
		})
		cert = append(cert, capem...)
	}
	return cert, pkey, nil
}

// withOptions set options for the Generator.
func (g *Generator) withOptions(opts ...Option) {
	for _, opt := range opts {
		opt.apply(g)
	}
}
