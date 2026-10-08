// Package keychain управляет сертификатами в связке ключей macOS через security(1).
package keychain

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/mikluko/meanziphra/internal/execerr"
	"github.com/mikluko/meanziphra/internal/pki"
)

// Keychain — путь к файлу связки ключей.
type Keychain string

// Default возвращает связку login текущего пользователя.
func Default() Keychain {
	home, _ := os.UserHomeDir()
	return Keychain(filepath.Join(home, "Library", "Keychains", "login.keychain-db"))
}

// Owned перечисляет сертификаты связки, которые являются якорем с CN name или выпущены им.
func (k Keychain) Owned(name string) ([]*x509.Certificate, error) {
	out, err := exec.Command("security", "find-certificate", "-a", "-p", string(k)).Output()
	if err != nil {
		return nil, fmt.Errorf("security find-certificate: %w", execerr.Wrap(err))
	}
	var all []*x509.Certificate
	for rest := out; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		all = append(all, cert)
	}
	return Ours(all, name), nil
}

// Ours отбирает из certs якорь с CN name и выпущенные им сертификаты.
func Ours(certs []*x509.Certificate, name string) []*x509.Certificate {
	var r []*x509.Certificate
	for _, c := range certs {
		if c.Subject.CommonName == name || c.Issuer.CommonName == name {
			r = append(r, c)
		}
	}
	return r
}

// Plan возвращает сертификаты из want, которых нет в installed, и сертификаты из installed, которых нет в want.
func Plan(installed, want []*x509.Certificate) (add, remove []*x509.Certificate) {
	has := func(set []*x509.Certificate, c *x509.Certificate) bool {
		for _, s := range set {
			if bytes.Equal(s.Raw, c.Raw) {
				return true
			}
		}
		return false
	}
	for _, c := range want {
		if !has(installed, c) {
			add = append(add, c)
		}
	}
	for _, c := range installed {
		if !has(want, c) {
			remove = append(remove, c)
		}
	}
	return add, remove
}

// Add импортирует cert; trusted делает его доверенным корнем, что macOS подтверждает паролем пользователя.
func (k Keychain) Add(cert *x509.Certificate, trusted bool) error {
	f, err := os.CreateTemp("", "meanziphra-*.crt")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(pki.EncodePEM(cert)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	args := []string{"add-certificates", "-k", string(k), f.Name()}
	if trusted {
		args = []string{"add-trusted-cert", "-r", "trustRoot", "-k", string(k), f.Name()}
	}
	return run(args)
}

// Remove удаляет cert вместе с его настройками доверия.
func (k Keychain) Remove(cert *x509.Certificate) error {
	sum := sha1.Sum(cert.Raw)
	return run([]string{"delete-certificate", "-t", "-Z", hex.EncodeToString(sum[:]), string(k)})
}

func run(args []string) error {
	cmd := exec.Command("security", args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("security %s: %w", args[0], err)
	}
	return nil
}
