package keychain

import (
	"crypto/x509"
	"testing"

	"github.com/mikluko/meanziphra/internal/pki"
	"github.com/mikluko/meanziphra/internal/pkitest"
)

func TestPlan(t *testing.T) {
	k := pkitest.Key(t)
	a, b, c := pkitest.SelfSigned(t, "a", k), pkitest.SelfSigned(t, "b", k), pkitest.SelfSigned(t, "c", k)
	add, remove := Plan([]*x509.Certificate{a, b}, []*x509.Certificate{b, c})
	if len(add) != 1 || !add[0].Equal(c) {
		t.Errorf("add = %v", add)
	}
	if len(remove) != 1 || !remove[0].Equal(a) {
		t.Errorf("remove = %v", remove)
	}
}

func TestOurs(t *testing.T) {
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
	got := Ours([]*x509.Certificate{ca.Root, ca.Sub, anchor, cross}, "Минцифры на поводке")
	if len(got) != 2 || !got[0].Equal(anchor) || !got[1].Equal(cross) {
		t.Errorf("Ours = %d certs", len(got))
	}
}
