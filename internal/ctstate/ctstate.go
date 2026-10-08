// Package ctstate хранит, докуда прочитаны журналы CT, и найденные в них имена со сроком действия и владельцем.
package ctstate

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"slices"
	"time"
)

const dateLayout = "2006-01-02"

var (
	oidOGRN  = asn1.ObjectIdentifier{1, 2, 643, 100, 1}
	oidINNLE = asn1.ObjectIdentifier{1, 2, 643, 100, 4}
)

type State struct {
	// Logs — сколько записей каждого журнала уже прочитано, по URL журнала.
	Logs map[string]int64 `json:"logs"`
	// Names — по каждому имени сведения из сертификата с самой поздней датой окончания.
	Names map[string]Name `json:"names"`
}

type Name struct {
	NotAfter string `json:"not_after"`
	Owner
}

// Owner — организация из subject сертификата: O, ИНН юрлица и ОГРН. Пустые поля в сертификате не указаны.
type Owner struct {
	Org  string `json:"org,omitempty"`
	INN  string `json:"inn,omitempty"`
	OGRN string `json:"ogrn,omitempty"`
}

// OwnerOf читает владельца из subject cert.
func OwnerOf(cert *x509.Certificate) Owner {
	var o Owner
	if len(cert.Subject.Organization) > 0 {
		o.Org = cert.Subject.Organization[0]
	}
	for _, a := range cert.Subject.Names {
		v, ok := a.Value.(string)
		if !ok {
			continue
		}
		switch {
		case a.Type.Equal(oidINNLE):
			o.INN = v
		case a.Type.Equal(oidOGRN):
			o.OGRN = v
		}
	}
	return o
}

// Load читает состояние из path; отсутствующий файл даёт пустое состояние.
func Load(path string) (*State, error) {
	s := &State{Logs: map[string]int64{}, Names: map[string]Name{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Logs == nil {
		s.Logs = map[string]int64{}
	}
	if s.Names == nil {
		s.Names = map[string]Name{}
	}
	return s, nil
}

// Save пишет состояние с ключами по алфавиту, по одному на строку, так что дифф показывает только изменения.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Add запоминает name из сертификата, действующего до notAfter, если это позже уже известной даты.
func (s *State) Add(name string, notAfter time.Time, owner Owner) {
	d := notAfter.UTC().Format(dateLayout)
	if d > s.Names[name].NotAfter {
		s.Names[name] = Name{NotAfter: d, Owner: owner}
	}
}

// Prune забывает имена, срок действия которых закончился раньше дня now.
func (s *State) Prune(now time.Time) {
	today := now.UTC().Format(dateLayout)
	for n, v := range s.Names {
		if v.NotAfter < today {
			delete(s.Names, n)
		}
	}
}

// Valid возвращает известные имена по алфавиту.
func (s *State) Valid() []string {
	r := make([]string, 0, len(s.Names))
	for n := range s.Names {
		r = append(r, n)
	}
	slices.Sort(r)
	return r
}
