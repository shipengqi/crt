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

// Gen return a crypto.Signer.
func (g *RsaKey) Gen() (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, g.bits)
}

// Encode to pem format.
func (g *RsaKey) Encode(pkey crypto.Signer) []byte {
	keyPem := &pem.Block{
		Type:  RsaKeyPrefix,
		Bytes: x509.MarshalPKCS1PrivateKey(pkey.(*rsa.PrivateKey)),
	}

	return pem.EncodeToMemory(keyPem)
}
