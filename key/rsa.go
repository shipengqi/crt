package key

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type RsaKey struct {
	bits int
}

// NewRsaKey return an RSA key generator.
// If the bit size less than 2048 bits, set to 2048 bits.
func NewRsaKey(bits int) *RsaKey {
	if bits < DefaultKeyLength {
		bits = DefaultKeyLength
	}
	return &RsaKey{bits: bits}
}

// Gen generates a public and private key pair.
// Returns a crypto.Singer.
func (g *RsaKey) Gen() (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, g.bits)
}

// Marshal returns an RSA private key in PKCS #1, ASN.1 DER form.
// This kind of key is commonly encoded in PEM blocks of type "RSA PRIVATE KEY".
// For PEM blocks, use the Encode method.
func (g *RsaKey) Marshal(pkey crypto.Signer, opts *MarshalOptions) ([]byte, error) {
	if opts == nil {
		opts = _defaultMarshalOptions
	}

	if !opts.IsPKCS8 {
		return g.MarshalPKCS1PrivateKey(pkey.(*rsa.PrivateKey), opts.Password)
	}
	return g.MarshalPKCS8PrivateKey(pkey)
}

// MarshalPKCS1PrivateKey converts an RSA private key to PKCS #1, ASN.1 DER form.
// And returns the private key encoded in PEM blocks.
func (g *RsaKey) MarshalPKCS1PrivateKey(pkey *rsa.PrivateKey, password []byte) ([]byte, error) {
	b := x509.MarshalPKCS1PrivateKey(pkey)
	if len(password) == 0 {
		return EncodeWithBlockType(b, RsaBlockType), nil
	}
	//nolint:staticcheck
	eb, err := x509.EncryptPEMBlock(rand.Reader, RsaBlockType, b, password, x509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(eb), nil
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
// And returns the private key encoded in PEM blocks.
func (g *RsaKey) MarshalPKCS8PrivateKey(pkey any) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(pkey)
	if err != nil {
		return nil, err
	}
	return EncodeWithBlockType(b, PKCCS8BlockType), nil
}
