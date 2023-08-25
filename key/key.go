package key

import (
	"crypto"
	"encoding/pem"
)

const (
	RsaBlockType         = "RSA PRIVATE KEY"
	EcdsaBlockType       = "EC PRIVATE KEY"
	PKCCS8BlockType      = "PRIVATE KEY"
	DefaultKeyLength     = 2048
	RecommendedKeyLength = 4096
)

var _defaultMarshalOptions = &MarshalOptions{
	IsPKCS8: false,
}

type Generator interface {
	// Gen generates a public and private key pair.
	// And returns a crypto.Singer.
	Gen() (crypto.Signer, error)
	// Marshal converts a private key to ASN.1 DER form.
	// And returns the private key encoded in PEM blocks.
	// The opts is optional.
	Marshal(pkey crypto.Signer, opts *MarshalOptions) ([]byte, error)
}

type MarshalOptions struct {
	// Password can be nil, otherwise use it to encrypt the private key.
	// If the IsPKCS8 is true, the Password will be ignored.
	// See https://github.com/golang/go/commit/57af9745bfad2c20ed6842878e373d6c5b79285a.
	Password []byte
	// IsPKCS8 whether to convert the private key to PKCS #8, ASN.1 DER form.
	IsPKCS8 bool
}

// EncodeWithBlockType returns the PEM encoding of b with the given block type.
// If b has invalid headers and cannot be encoded,
// Encode returns nil.
func EncodeWithBlockType(b []byte, blockType string) []byte {
	keyPem := &pem.Block{
		Type:  blockType,
		Bytes: b,
	}

	return pem.EncodeToMemory(keyPem)
}
