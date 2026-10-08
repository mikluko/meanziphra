// Package probe получает цепочки с живых хостов и проверяет их через якорь.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

// FetchChain возвращает сертификаты, которые host отдаёт на порту 443, без проверки.
func FetchChain(ctx context.Context, host string) ([]*x509.Certificate, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    &tls.Config{ServerName: host, InsecureSkipVerify: true},
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	chain := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("no certificates served")
	}
	return chain, nil
}

// Verify проверяет chain[0] для host, доверяя только anchor.
// Остальная цепочка, включая присланный сервером корень, передаётся как недоверенные промежуточные.
func Verify(anchor *x509.Certificate, crosses, chain []*x509.Certificate, host string) error {
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	inter := x509.NewCertPool()
	for _, c := range crosses {
		inter.AddCert(c)
	}
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
	return err
}
