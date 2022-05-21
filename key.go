package crt

import "crypto"

const (
	RsaKeyPrefix         = "RSA PRIVATE KEY"
	EcdsaKeyPrefix       = "ECDSA PRIVATE KEY"
	DefaultKeyLength     = 2048
	RecommendedKeyLength = 4096
)

const (
	RsaKeyType Type = iota
	EcdsaKeyType
)

type Type int

type Interface interface {
	Gen() (crypto.Signer, error)
	Encode(key crypto.Signer) []byte
}
