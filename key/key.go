package key

import "crypto"

const (
	RsaKeyPrefix         = "RSA PRIVATE KEY"
	EcdsaKeyPrefix       = "ECDSA PRIVATE KEY"
	DefaultKeyLength     = 2048
	RecommendedKeyLength = 4096
)

type Generator interface {
	// Gen return a crypto.Signer.
	Gen() (crypto.Signer, error)
	// Encode to pem format
	Encode(key crypto.Signer) []byte
}
