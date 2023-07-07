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
func NewEcdsaKey() *EcdsaKey {
	return &EcdsaKey{curve: elliptic.P256()}
}

// BlockType returns block type "EC PRIVATE KEY"
func (g *EcdsaKey) BlockType() string {
	return EcdsaBlockType
}

// Gen generates a public and private key pair.
// Returns a crypto.Singer.
func (g *EcdsaKey) Gen() (crypto.Signer, error) {
	return ecdsa.GenerateKey(g.curve, rand.Reader)
}

// Marshal returns an EC private key in SEC 1, ASN.1 DER form
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY".
// For PEM blocks, use the Encode method.
func (g *EcdsaKey) Marshal(pkey crypto.Signer) ([]byte, error) {
	return x509.MarshalECPrivateKey(pkey.(*ecdsa.PrivateKey))
}

// Encode returns the PEM encoding of b.
// If b has invalid headers and cannot be encoded,
// Encode returns nil.
func (g *EcdsaKey) Encode(b []byte) []byte {
	keyPem := &pem.Block{
		Type:  EcdsaBlockType,
		Bytes: b,
	}

	return pem.EncodeToMemory(keyPem)
}
