package key

import (
	"crypto"
)

const (
	RsaBlockType         = "RSA PRIVATE KEY"
	EcdsaBlockType       = "EC PRIVATE KEY"
	PKCCS8BlockType      = "PRIVATE KEY"
	DefaultKeyLength     = 2048
	RecommendedKeyLength = 4096
)

const (
	PKFormatPKCS8 PKFormat = "pkcs8"
	PKFormatPKCS1 PKFormat = "pkcs1"
)

var _defaultMarshalOptions = &MarshalOptions{
	Format: PKFormatPKCS8,
}

type PKFormat string

type Generator interface {
	// Gen generates a public and private key pair.
	// Returns a crypto.Singer.
	Gen() (crypto.Signer, error)
	// Marshal returns a private key in ASN.1 DER form
	Marshal(pkey crypto.Signer, opts *MarshalOptions) ([]byte, error)
}

type MarshalOptions struct {
	Password []byte
	Format   PKFormat
}
