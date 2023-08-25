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
// And returns a crypto.Singer.
func (g *EcdsaKey) Gen() (crypto.Signer, error) {
	return ecdsa.GenerateKey(g.curve, rand.Reader)
}

// Marshal converts an EC private key to SEC 1 or PKCS#8, ASN.1 DER form.
// And returns the private key encoded in PEM blocks.
func (g *EcdsaKey) Marshal(pkey crypto.Signer, opts *MarshalOptions) ([]byte, error) {
	if opts == nil {
		opts = _defaultMarshalOptions
	}
	if !opts.IsPKCS8 {
		return g.MarshalECPrivateKey(pkey.(*ecdsa.PrivateKey), opts.Password)
	}
	return g.MarshalPKCS8PrivateKey(pkey)
}

// MarshalECPrivateKey converts an EC private key to SEC 1, ASN.1 DER form.
// And returns the private key encoded in PEM blocks.
func (g *EcdsaKey) MarshalECPrivateKey(pkey *ecdsa.PrivateKey, password []byte) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(pkey)
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return EncodeWithBlockType(b, EcdsaBlockType), nil
	}
	//nolint:staticcheck
	eb, err := x509.EncryptPEMBlock(rand.Reader, EcdsaBlockType, b, password, x509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(eb), nil
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
// And returns the private key encoded in PEM blocks.
func (g *EcdsaKey) MarshalPKCS8PrivateKey(pkey interface{}) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(pkey)
	if err != nil {
		return nil, err
	}
	return EncodeWithBlockType(b, PKCCS8BlockType), nil
}
