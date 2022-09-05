package crt

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithKeyUsage(t *testing.T)  {
	t.Run("should be equal", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
		)
		cert2 := New(
			WithServerType(),
			WithKeyUsage(x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment),
		)
		assert.Equal(t, cert.keyUsage, cert2.keyUsage)
	})

	t.Run("should be 0", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithKeyUsage(),
		)
		assert.Equal(t, 0, int(cert.keyUsage))
	})

	t.Run("should be 1", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithKeyUsage(x509.KeyUsageDigitalSignature),
		)
		assert.Equal(t, 1, int(cert.keyUsage))
	})

	t.Run("should be 5", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithKeyUsage(x509.KeyUsageDigitalSignature),
			WithKeyUsage(x509.KeyUsageKeyEncipherment),
		)

		assert.Equal(t, 5, int(cert.keyUsage))
	})
}
