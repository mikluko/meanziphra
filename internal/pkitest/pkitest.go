// Package pkitest строит для тестов чужой УЦ: самоподписанный корень, промежуточный УЦ и листовые сертификаты.
package pkitest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

type CA struct {
	Root, Sub *x509.Certificate
	subKey    crypto.Signer
}

func Key(t testing.TB) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// SelfSigned выпускает самоподписанный сертификат УЦ с CN cn.
func SelfSigned(t testing.TB, cn string, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := caTemplate(t, cn)
	return sign(t, tmpl, tmpl, key.Public(), key)
}

// NewCA строит корень «Foreign Root» и промежуточный УЦ «Foreign Sub» под ним.
func NewCA(t testing.TB) CA {
	t.Helper()
	rootKey, subKey := Key(t), Key(t)
	root := SelfSigned(t, "Foreign Root", rootKey)
	sub := sign(t, caTemplate(t, "Foreign Sub"), root, subKey.Public(), rootKey)
	return CA{Root: root, Sub: sub, subKey: subKey}
}

// Leaf выпускает от Sub серверный сертификат на имена dns.
func (ca CA) Leaf(t testing.TB, dns ...string) *x509.Certificate {
	t.Helper()
	return Leaf(t, ca.Sub, ca.subKey, dns...)
}

// Leaf выпускает от parent серверный сертификат на имена dns.
func Leaf(t testing.TB, parent *x509.Certificate, parentKey crypto.Signer, dns ...string) *x509.Certificate {
	t.Helper()
	k := Key(t)
	return sign(t, &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: dns[0]},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, parent, k.Public(), parentKey)
}

func caTemplate(t testing.TB, cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func sign(t testing.TB, tmpl, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func serial(t testing.TB) *big.Int {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
