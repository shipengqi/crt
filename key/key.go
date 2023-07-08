package key

import "crypto"

const (
	RsaBlockType         = "RSA PRIVATE KEY"
	EcdsaBlockType       = "EC PRIVATE KEY"
	DefaultKeyLength     = 2048
	RecommendedKeyLength = 4096
)

type Generator interface {
	// BlockType returns the block type.
	BlockType() string
	// Gen generates a public and private key pair.
	// Returns a crypto.Singer.
	Gen() (crypto.Signer, error)
	// Marshal returns a private key in ASN.1 DER form
	Marshal(pkey crypto.Signer) ([]byte, error)
	// Encode returns the PEM encoding of b.
	// If b has invalid headers and cannot be encoded,
	// Encode returns nil.
	Encode([]byte) []byte
}
