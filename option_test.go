package crt_test

import (
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/shipengqi/crt"
)

func TestWithKeyUsage(t *testing.T) {

	g := createGenWithCA(t)

	t.Run("should be equal", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
		)
		cert2 := New(
			WithServerType(),
			WithKeyUsage(x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment),
		)
		created1, _, err := g.Create(cert)
		assert.Nil(t, err)
		parsed1, err := parseCertBytes(created1)
		assert.Nil(t, err)

		created2, _, err := g.Create(cert2)
		assert.Nil(t, err)
		parsed2, err := parseCertBytes(created2)
		assert.Nil(t, err)

		assert.Equal(t, parsed1.KeyUsage, parsed2.KeyUsage)
	})

	t.Run("should be 0", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithKeyUsage(),
		)
		created, _, err := g.Create(cert)
		assert.Nil(t, err)
		parsed, err := parseCertBytes(created)
		assert.Nil(t, err)
		assert.Equal(t, 0, int(parsed.KeyUsage))
	})

	t.Run("should be 1", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithKeyUsage(x509.KeyUsageDigitalSignature),
		)
		created, _, err := g.Create(cert)
		assert.Nil(t, err)
		parsed, err := parseCertBytes(created)
		assert.Nil(t, err)
		assert.Equal(t, 1, int(parsed.KeyUsage))
	})

	t.Run("should be 5", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithKeyUsage(x509.KeyUsageDigitalSignature),
			WithKeyUsage(x509.KeyUsageKeyEncipherment),
		)
		created, _, err := g.Create(cert)
		assert.Nil(t, err)
		parsed, err := parseCertBytes(created)
		assert.Nil(t, err)


		assert.Equal(t, 5, int(parsed.KeyUsage))
	})
}

func TestWithValidity(t *testing.T) {
	g := createGenWithCA(t)

	t.Run("expires in one day", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithValidity(time.Hour*24),
		)

		created, _, err := g.Create(cert)
		assert.Nil(t, err)
		parsed, err := parseCertBytes(created)
		assert.Nil(t, err)
		assert.Equal(t, parsed.NotBefore.Add(24*time.Hour), parsed.NotAfter)
	})
}

func TestWithDNSNames(t *testing.T) {
	g := createGenWithCA(t)

	t.Run("DNSNames length should be 1", func(t *testing.T) {
		cert := New(
			WithServerType(),
			WithDNSNames("test1"),
		)

		created, _, err := g.Create(cert)
		assert.Nil(t, err)
		parsed, err := parseCertBytes(created)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(parsed.DNSNames))
		assert.Equal(t, "test1", parsed.DNSNames[0])
	})
}

func TestWithIPs(t *testing.T) {
	g := createGenWithCA(t)

	cert := New(
		WithServerType(),
		WithIPs(net.ParseIP("10.0.0.1")),
	)

	created, _, err := g.Create(cert)
	assert.Nil(t, err)
	parsed, err := parseCertBytes(created)
	assert.Nil(t, err)

	assert.Equal(t, 1, len(parsed.IPAddresses))
	assert.Equal(t, "10.0.0.1", parsed.IPAddresses[0].String())
}

func TestWithOrganizations(t *testing.T) {
	g := createGenWithCA(t)

	cert := New(
		WithServerType(),
		WithOrganizations("test"),
	)

	created, _, err := g.Create(cert)
	assert.Nil(t, err)
	parsed, err := parseCertBytes(created)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(parsed.Subject.Organization))
	assert.Equal(t, "test", parsed.Subject.Organization[0])
}
