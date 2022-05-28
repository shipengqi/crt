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
	return optionFunc(func(a *Certificate) {
		a.cn = cn
	})
}

// WithValidity is used to set the validity of the certificate.
func WithValidity(validity time.Duration) Option {
	return optionFunc(func(a *Certificate) {
		a.validity = validity
	})
}

// WithDNSNames is used to set the DNS Name values of the certificate.
func WithDNSNames(dns ...string) Option {
	return optionFunc(func(a *Certificate) {
		a.dnsNames = dns
	})
}

// WithIPs is used to set the IP Address values of the certificate.
func WithIPs(ip ...net.IP) Option {
	return optionFunc(func(a *Certificate) {
		a.ips = ip
	})
}

// WithKeyUsage is used to set the x509.KeyUsage of the certificate.
func WithKeyUsage(keyUsage x509.KeyUsage) Option {
	return optionFunc(func(a *Certificate) {
		a.keyUsage = keyUsage
	})
}

// WithExtKeyUsages is used to set the x509.ExtKeyUsage values of the certificate.
func WithExtKeyUsages(extKeyUsage ...x509.ExtKeyUsage) Option {
	return optionFunc(func(a *Certificate) {
		a.extKeyUsages = extKeyUsage
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
	return optionFunc(func(a *Certificate) {
		a.ctype = t
	})
}

func appendExtKeyUsages(extKeyUsage ...x509.ExtKeyUsage) Option {
	return optionFunc(func(a *Certificate) {
		a.extKeyUsages = append(a.extKeyUsages, extKeyUsage...)
	})
}
