package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

type EcdsaKey struct {
	curve elliptic.Curve
}

// NewEcdsaKey return an Ecdsa key generator.
func NewEcdsaKey(curve elliptic.Curve) *EcdsaKey {
	if curve == nil {
		curve = elliptic.P256()
	}
	return &EcdsaKey{curve: curve}
}

// Gen generates a public and private key pair.
// Returns a crypto.Singer.
func (g *EcdsaKey) Gen() (crypto.Signer, error) {
	return ecdsa.GenerateKey(g.curve, rand.Reader)
}

// Marshal converts an EC private key to SEC 1 or PKCS#8, ASN.1 DER form
func (g *EcdsaKey) Marshal(pkey crypto.Signer, opts *MarshalOptions) ([]byte, error) {
	if opts == nil {
		opts = _defaultMarshalOptions
	}
	if opts.Format == PKFormatPKCS1 {
		return g.MarshalECPrivateKey(pkey.(*ecdsa.PrivateKey), opts.Password)
	}
	return g.MarshalPKCS8PrivateKey(pkey)
}

// MarshalECPrivateKey converts an EC private key to SEC 1, ASN.1 DER form.
// Returns the private key encoded in PEM blocks.
func (g *EcdsaKey) MarshalECPrivateKey(pkey *ecdsa.PrivateKey, password []byte) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(pkey)
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return g.encode(b), nil
	}
	//nolint:staticcheck
	eb, err := x509.EncryptPEMBlock(rand.Reader, EcdsaBlockType, b, password, x509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(eb), nil
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
// Returns the private key encoded in PEM blocks.
func (g *EcdsaKey) MarshalPKCS8PrivateKey(pkey any) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(pkey)
	if err != nil {
		return nil, err
	}
	return g.encode(b), nil
}

// encode returns the PEM encoding of b.
// If b has invalid headers and cannot be encoded,
// encode returns nil.
func (g *EcdsaKey) encode(b []byte) []byte {
	keyPem := &pem.Block{
		Type:  EcdsaBlockType,
		Bytes: b,
	}

	return pem.EncodeToMemory(keyPem)
}
