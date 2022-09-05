package crt

import (
	"crypto/x509"
	"net"
	"time"
)

// Option defines optional parameters for initializing the certificate
// structure.
type Option interface {
	apply(c *Certificate)
}

// optionFunc wraps a func, so it satisfies the Option interface.
type optionFunc func(*Certificate)

func (fn optionFunc) apply(c *Certificate) {
	fn(c)
}

// WithCN is used to set the CommonName.
func WithCN(cn string) Option {
	return optionFunc(func(c *Certificate) {
		c.cn = cn
	})
}

// WithValidity is used to set the validity of the certificate.
func WithValidity(validity time.Duration) Option {
	return optionFunc(func(c *Certificate) {
		c.validity = validity
	})
}

// WithDNSNames is used to set the DNS Name values of the certificate.
func WithDNSNames(dns ...string) Option {
	return optionFunc(func(c *Certificate) {
		c.dnsNames = dns
	})
}

// WithIPs is used to set the IP Address values of the certificate.
func WithIPs(ip ...net.IP) Option {
	return optionFunc(func(c *Certificate) {
		c.ips = ip
	})
}

// WithKeyUsage is used to set the x509.KeyUsage of the certificate.
func WithKeyUsage(keyUsage ...x509.KeyUsage) Option {
	return optionFunc(func(c *Certificate) {
		if len(keyUsage) == 0 {
			return
		}
		var merged x509.KeyUsage
		if len(keyUsage) == 1 {
			merged = keyUsage[0]
		} else {
			merged = keyUsage[0]
			for i := 1; i < len(keyUsage); i++ {
				merged = merged | keyUsage[i]
			}
		}
		if c.keyUsage != 0 {
			c.keyUsage = c.keyUsage | merged
		} else {
			c.keyUsage = merged
		}
	})
}

// WithExtKeyUsages is used to set the x509.ExtKeyUsage values of the certificate.
func WithExtKeyUsages(extKeyUsage ...x509.ExtKeyUsage) Option {
	return optionFunc(func(c *Certificate) {
		c.extKeyUsages = extKeyUsage
	})
}

// WithOrganizations is used to set the Organization values of the certificate.
func WithOrganizations(org ...string) Option {
	return optionFunc(func(c *Certificate) {
		c.organizations = org
	})
}

// WithCAType is used to set the CA certificate type.
func WithCAType() Option {
	return withType(_caType)
}

// WithServerType is used to set the Server certificate type.
func WithServerType() Option {
	return withType(_serverType)
}

// WithClientType is used to set the Client certificate type.
func WithClientType() Option {
	return withType(_clientType)
}

func withType(t int) Option {
	return optionFunc(func(c *Certificate) {
		c.ctype = t
	})
}

func appendExtKeyUsages(extKeyUsage ...x509.ExtKeyUsage) Option {
	return optionFunc(func(c *Certificate) {
		c.extKeyUsages = append(c.extKeyUsages, extKeyUsage...)
	})
}
