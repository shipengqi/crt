package crt

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	_defaultCACommonName = "CRT GENERATOR CA"
	_defaultCADuration   = time.Hour * 24 * 366 * 10
	_defaultCertDuration = time.Hour * 24 * 365
)

const (
	_caType = iota + 1
	_clientType
	_serverType
)

// Certificate is the main structure of a Certificate.
type Certificate struct {
	cn            string
	ctype         int
	validity      time.Duration
	keyUsage      x509.KeyUsage
	organizations []string
	dnsNames      []string
	ips           []net.IP
	extKeyUsages  []x509.ExtKeyUsage
}

// New create a new Certificate.
func New(opts ...Option) *Certificate {
	c := &Certificate{}
	c.withOptions(opts...)
	c.completeOptions()

	return c
}

// NewCACert create a new CA Certificate.
func NewCACert(opts ...Option) *Certificate {
	defaults := []Option{
		WithCN(_defaultCACommonName),
	}
	defaults = append(defaults, opts...)

	merged := append(defaults, WithCAType())

	return New(merged...)
}

// NewClientCert create a new Client Certificate.
func NewClientCert(opts ...Option) *Certificate {
	cn, _ := os.Hostname()
	defaults := []Option{
		WithCN(cn),
		WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
	}
	defaults = append(defaults, opts...)
	merged := append(defaults,
		appendExtKeyUsages(x509.ExtKeyUsageClientAuth),
		WithClientType())

	return New(merged...)
}

// NewServerCert create a new Server Certificate.
func NewServerCert(opts ...Option) *Certificate {
	cn, _ := os.Hostname()
	defaults := []Option{
		WithCN(cn),
		WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
	}
	defaults = append(defaults, opts...)
	merged := append(defaults,
		appendExtKeyUsages(x509.ExtKeyUsageServerAuth),
		WithServerType())

	return New(merged...)
}

// Gen generates a new x509.Certificate.
func (c *Certificate) Gen() *x509.Certificate {
	subject := pkix.Name{
		CommonName: c.cn,
	}
	subject.Organization = c.organizations
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<63-1)) // 9223372036854775808 - 1
	obj := &x509.Certificate{
		SerialNumber:          n,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(c.validity),
		BasicConstraintsValid: true,
		IsCA:                  c.IsCA(),
		KeyUsage:              c.keyUsage,
		ExtKeyUsage:           c.extKeyUsages,
	}

	if len(c.dnsNames) > 0 {
		obj.DNSNames = deduplicatestr(c.dnsNames)
	}

	if len(c.ips) > 0 {
		obj.IPAddresses = deduplicateips(c.ips)
	}

	return obj
}

// IsCA return whether the certificate is a CA certificate.
func (c *Certificate) IsCA() bool {
	return c.ctype == _caType
}

// IsClientCert return whether the certificate is a Client certificate.
func (c *Certificate) IsClientCert() bool {
	if c.ctype == _clientType {
		return true
	}

	for _, v := range c.extKeyUsages {
		if v == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

// IsServerCert return whether the certificate is a Server certificate.
func (c *Certificate) IsServerCert() bool {
	if c.ctype == _serverType {
		return true
	}
	for _, v := range c.extKeyUsages {
		if v == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

// withOptions set options for the Certificate
func (c *Certificate) withOptions(opts ...Option) {
	for _, opt := range opts {
		opt.apply(c)
	}
}

// completeOptions completes options of the Certificate
func (c *Certificate) completeOptions() {
	if c.validity == 0 {
		c.validity = _defaultCertDuration
		if c.IsCA() {
			c.validity = _defaultCADuration
		}
	}
}
