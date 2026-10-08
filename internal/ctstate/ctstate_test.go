package ctstate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	day := func(d string) time.Time {
		v, _ := time.Parse(dateLayout, d)
		return v
	}
	s.Add("a.ru", day("2026-12-01"), Owner{Org: "A"})
	s.Add("a.ru", day("2026-11-01"), Owner{Org: "old A"})
	s.Add("b.ru", day("2026-10-07"), Owner{})
	s.Add("c.ru", day("2026-10-08"), Owner{})
	s.Logs["https://log/"] = 42
	s.Prune(day("2026-10-08").Add(12 * time.Hour))
	if got, want := s.Valid(), []string{"a.ru", "c.ru"}; !slices.Equal(got, want) {
		t.Errorf("Valid = %v, want %v", got, want)
	}
	if a := s.Names["a.ru"]; a.NotAfter != "2026-12-01" || a.Org != "A" {
		t.Errorf("a.ru = %+v, want the later certificate", a)
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Logs["https://log/"] != 42 || !slices.Equal(s2.Valid(), s.Valid()) {
		t.Errorf("round trip lost data: %+v", s2)
	}
	if err := s2.Save(path); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Error("saving the same state twice gave different files")
	}
}

func TestOwnerOf(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{
		Organization: []string{"TBank"},
		Names: []pkix.AttributeTypeAndValue{
			{Type: oidINNLE, Value: "7710140679"},
			{Type: oidOGRN, Value: "1027739642281"},
		},
	}}
	if got, want := OwnerOf(cert), (Owner{Org: "TBank", INN: "7710140679", OGRN: "1027739642281"}); got != want {
		t.Errorf("OwnerOf = %+v, want %+v", got, want)
	}
}
