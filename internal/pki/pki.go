// Package pki выпускает якорь и кросс-сертификаты и читает сертификаты с диска.
package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"slices"
	"strings"
	"time"
)

// LoadRoot читает сертификат в PEM или DER и возвращает ошибку, если его SHA-256 не совпадает с pin.
func LoadRoot(path, pin string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := ParseRoot(b, pin)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cert, nil
}

// ParseRoot разбирает сертификат в PEM или DER и возвращает ошибку, если его SHA-256 не совпадает с pin.
func ParseRoot(b []byte, pin string) (*x509.Certificate, error) {
	cert, err := ParseCert(b)
	if err != nil {
		return nil, err
	}
	if err := CheckPin(cert, pin); err != nil {
		return nil, err
	}
	return cert, nil
}

// CheckPin возвращает ошибку, если SHA-256 cert не совпадает с pin. Регистр и двоеточия в pin не важны.
func CheckPin(cert *x509.Certificate, pin string) error {
	if got := Fingerprint(cert); normalize(pin) != normalize(got) {
		return fmt.Errorf("sha256 %s, pinned %s", got, pin)
	}
	return nil
}

// ReadCert читает первый сертификат файла в PEM или DER.
func ReadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCert(b)
}

// ParseCert разбирает первый сертификат в PEM или DER.
func ParseCert(b []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(b); block != nil {
		b = block.Bytes
	}
	return x509.ParseCertificate(b)
}

func WriteCert(path string, cert *x509.Certificate) error {
	return os.WriteFile(path, EncodePEM(cert), 0o644)
}

// WriteCerts пишет certs в один файл PEM подряд.
func WriteCerts(path string, certs []*x509.Certificate) error {
	var b []byte
	for _, c := range certs {
		b = append(b, EncodePEM(c)...)
	}
	return os.WriteFile(path, b, 0o644)
}

// ReadCerts читает все сертификаты из файла PEM.
func ReadCerts(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no certificates", path)
	}
	return certs, nil
}

func EncodePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// Fingerprint возвращает SHA-256 сертификата в виде AA:BB:….
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func normalize(fp string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(fp))
}

// ReusableAnchor возвращает якорь из path, если он наш, выпущен на key, действует до notAfter
// и ограничен в точности доменами permit, иначе nil.
func ReusableAnchor(path, name string, key crypto.Signer, notAfter time.Time, permit []string) (*x509.Certificate, error) {
	cert, err := ReadCert(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(key.Public()) || cert.Subject.CommonName != name || cert.NotAfter.Before(notAfter) ||
		!slices.Equal(cert.PermittedDNSDomains, permit) {
		return nil, nil
	}
	return cert, nil
}

// NewAnchor выпускает самоподписанный якорь с CN name, ограниченный доменами permit,
// чтобы и утёкший ключ якоря не подписал ничего вне них.
func NewAnchor(name string, key crypto.Signer, notAfter time.Time, permit []string) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: name},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    notAfter,
		IsCA:                        true,
		BasicConstraintsValid:       true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomains:         permit,
		PermittedDNSDomainsCritical: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CrossSign перевыпускает root от имени anchor с тем же subject, ключом и key ID, ограничивая его доменами permit.
// Цепочки, выданные под root, строятся через кросс-сертификат и наследуют ограничение.
func CrossSign(anchor *x509.Certificate, key crypto.Signer, root *x509.Certificate, permit []string) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		RawSubject:                  root.RawSubject,
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    root.NotAfter,
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  root.MaxPathLen,
		MaxPathLenZero:              root.MaxPathLenZero,
		KeyUsage:                    root.KeyUsage,
		SubjectKeyId:                root.SubjectKeyId,
		PermittedDNSDomains:         permit,
		PermittedDNSDomainsCritical: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, anchor, root.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// VerifyLogged разбирает сертификат или предсертификат der и проверяет, что цепочка chain, принятая журналом
// вместе с ним, ведёт к root: каждый сертификат подписан следующим, а последний — это root или подписан им.
func VerifyLogged(der []byte, chain [][]byte, root *x509.Certificate) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cur := leaf
	for _, b := range chain {
		if bytes.Equal(b, root.Raw) {
			break
		}
		next, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, err
		}
		if err := cur.CheckSignatureFrom(next); err != nil {
			return nil, err
		}
		cur = next
	}
	if err := cur.CheckSignatureFrom(root); err != nil {
		return nil, err
	}
	return leaf, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
