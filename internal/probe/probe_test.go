package probe

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/mikluko/meanziphra/internal/pki"
	"github.com/mikluko/meanziphra/internal/pkitest"
)

func TestVerify_ConfinesRoot(t *testing.T) {
	ca := pkitest.NewCA(t)
	k := pkitest.Key(t)
	anchor, err := pki.NewAnchor("Минцифры на поводке", k, ca.Root.NotAfter, []string{"bank.test"})
	if err != nil {
		t.Fatal(err)
	}
	cross, err := pki.CrossSign(anchor, k, ca.Root, []string{"bank.test"})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		dns  []string
		ok   bool
	}{
		{"bank.test", []string{"bank.test"}, true},
		{"online.bank.test", []string{"online.bank.test"}, true},
		{"evil.test", []string{"evil.test"}, false},
		{"notbank.test", []string{"notbank.test"}, false},
		{"bank.test", []string{"bank.test", "evil.test"}, false},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.dns, ","), func(t *testing.T) {
			// Сервер присылает и сам чужой корень, как это делают настоящие серверы.
			chain := []*x509.Certificate{ca.Leaf(t, tt.dns...), ca.Sub, ca.Root}
			err := Verify(anchor, []*x509.Certificate{cross}, chain, tt.host)
			if (err == nil) != tt.ok {
				t.Fatalf("verify %s: err = %v, want ok = %v", tt.host, err, tt.ok)
			}
		})
	}
}

// Утёкший ключ якоря не должен подписывать сертификаты вне permit.
func TestVerify_ConfinesAnchorKey(t *testing.T) {
	k := pkitest.Key(t)
	anchor, err := pki.NewAnchor("a", k, time.Now().Add(time.Hour), []string{"bank.test"})
	if err != nil {
		t.Fatal(err)
	}
	for host, ok := range map[string]bool{"online.bank.test": true, "evil.test": false} {
		chain := []*x509.Certificate{pkitest.Leaf(t, anchor, k, host)}
		if err := Verify(anchor, nil, chain, host); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok = %v", host, err, ok)
		}
	}
}
