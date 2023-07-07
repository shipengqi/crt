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

// BlockType returns block type "EC PRIVATE KEY"
func (g *RsaKey) BlockType() string {
	return RsaBlockType
}

// Gen generates a public and private key pair.
// Returns a crypto.Singer.
func (g *RsaKey) Gen() (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, g.bits)
}

// Marshal returns an RSA private key in PKCS #1, ASN.1 DER form.
// This kind of key is commonly encoded in PEM blocks of type "RSA PRIVATE KEY".
// For PEM blocks, use the Encode method.
func (g *RsaKey) Marshal(pkey crypto.Signer) ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(pkey.(*rsa.PrivateKey)), nil
}

// Encode returns the PEM encoding of b.
// If b has invalid headers and cannot be encoded,
// Encode returns nil.
func (g *RsaKey) Encode(b []byte) []byte {
	keyPem := &pem.Block{
		Type:  RsaBlockType,
		Bytes: b,
	}

	return pem.EncodeToMemory(keyPem)
}
