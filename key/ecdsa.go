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

// NewEcdsaKey return a Ecdsa key generator.
func NewEcdsaKey() *EcdsaKey {
	return &EcdsaKey{curve: elliptic.P256()}
}

// Gen return a crypto.Signer.
func (g *EcdsaKey) Gen() (crypto.Signer, error) {
	return ecdsa.GenerateKey(g.curve, rand.Reader)
}

// Encode to pem format.
func (g *EcdsaKey) Encode(pkey crypto.Signer) []byte {
	x509Encoded, _ := x509.MarshalECPrivateKey(pkey.(*ecdsa.PrivateKey))
	keyPem := &pem.Block{
		Type:  EcdsaKeyPrefix,
		Bytes: x509Encoded,
	}

	return pem.EncodeToMemory(keyPem)
}
