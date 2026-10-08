// Package anchorkey находит закрытый ключ якоря по значению anchor.key.
package anchorkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mikluko/meanziphra/internal/execerr"
)

// Source — разобранное значение anchor.key.
type Source struct {
	Scheme string // "" для эфемерного ключа, "file" или "op"
	Ref    string
}

// ParseSource разбирает anchor.key: пустое значение — эфемерный ключ, значение без схемы — путь к файлу.
func ParseSource(s string) (Source, error) {
	if s == "" {
		return Source{}, nil
	}
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return Source{Scheme: "file", Ref: s}, nil
	}
	switch scheme {
	case "file":
		return Source{Scheme: "file", Ref: rest}, nil
	case "op":
		return Source{Scheme: "op", Ref: s}, nil
	}
	return Source{}, fmt.Errorf("anchor.key %q: unsupported scheme %q", s, scheme)
}

// Persistent сообщает, переживает ли ключ этот запуск.
func (s Source) Persistent() bool {
	return s.Scheme != ""
}

// ErrDiskKey — ключ в файле запрошен без разрешения держать ключ на диске.
var ErrDiskKey = errors.New("anchor key file refused: the key would be on disk; pass -insecure to allow it")

// Load возвращает ключ и признак того, что он только что создан. Относительный путь отсчитывается от dir.
// Ключ в файле, созданный или существующий, загружается только при allowDisk, иначе ErrDiskKey.
// Отсутствующий файл создаётся с правами 0600; отсутствующая запись op:// — ошибка.
func Load(s Source, dir string, allowDisk bool) (crypto.Signer, bool, error) {
	if s.Scheme == "file" && !allowDisk {
		return nil, false, ErrDiskKey
	}
	switch s.Scheme {
	case "":
		k, err := Generate()
		return k, true, err
	case "op":
		out, err := exec.Command("op", "read", "--no-newline", s.Ref).Output()
		if err != nil {
			return nil, false, fmt.Errorf("op read %s: %w", s.Ref, execerr.Wrap(err))
		}
		k, err := Parse(out)
		return k, false, err
	}
	path := s.Ref
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		k, err := Generate()
		if err != nil {
			return nil, false, err
		}
		return k, true, write(path, k)
	}
	if err != nil {
		return nil, false, err
	}
	k, err := Parse(b)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	return k, false, nil
}

// Generate создаёт ключ ECDSA P-256.
func Generate() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func write(path string, k crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Parse принимает PEM в PKCS#8, SEC 1 или PKCS#1.
func Parse(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	var k any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%T cannot sign", k)
	}
	return s, nil
}
