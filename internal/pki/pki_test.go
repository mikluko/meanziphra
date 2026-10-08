package pki

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikluko/meanziphra/internal/pkitest"
)

func TestCrossSign_KeepsRootIdentity(t *testing.T) {
	ca := pkitest.NewCA(t)
	k := pkitest.Key(t)
	anchor, err := NewAnchor("a", k, ca.Root.NotAfter, []string{"bank.test"})
	if err != nil {
		t.Fatal(err)
	}
	cross, err := CrossSign(anchor, k, ca.Root, []string{"bank.test"})
	if err != nil {
		t.Fatal(err)
	}
	if string(cross.RawSubject) != string(ca.Root.RawSubject) {
		t.Errorf("subject = %s, want %s", cross.Subject, ca.Root.Subject)
	}
	if string(cross.SubjectKeyId) != string(ca.Root.SubjectKeyId) {
		t.Errorf("subject key id differs from root")
	}
	if !cross.PermittedDNSDomainsCritical {
		t.Errorf("name constraints not critical")
	}
	if !cross.NotAfter.Equal(ca.Root.NotAfter) {
		t.Errorf("not after = %v, want %v", cross.NotAfter, ca.Root.NotAfter)
	}
	if err := cross.CheckSignatureFrom(anchor); err != nil {
		t.Errorf("not signed by anchor: %v", err)
	}
}

func TestLoadRoot_Pin(t *testing.T) {
	ca := pkitest.NewCA(t)
	path := filepath.Join(t.TempDir(), "root.pem")
	if err := WriteCert(path, ca.Root); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoot(path, strings.ToLower(strings.ReplaceAll(Fingerprint(ca.Root), ":", ""))); err != nil {
		t.Errorf("pin without colons, lower case: %v", err)
	}
	if _, err := LoadRoot(path, strings.Repeat("00:", 31)+"00"); err == nil {
		t.Error("wrong pin accepted")
	}
}

func TestReusableAnchor(t *testing.T) {
	k := pkitest.Key(t)
	ca := pkitest.NewCA(t)
	permit := []string{"bank.test"}
	anchor, err := NewAnchor("a", k, ca.Root.NotAfter, permit)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "anchor.crt")
	if got, err := ReusableAnchor(path, "a", k, ca.Root.NotAfter, permit); err != nil || got != nil {
		t.Fatalf("missing file: %v, %v", got, err)
	}
	if err := WriteCert(path, anchor); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReusableAnchor(path, "a", k, ca.Root.NotAfter, permit); got == nil {
		t.Error("matching anchor not reused")
	}
	if got, _ := ReusableAnchor(path, "b", k, ca.Root.NotAfter, permit); got != nil {
		t.Error("anchor reused under another name")
	}
	if got, _ := ReusableAnchor(path, "a", pkitest.Key(t), ca.Root.NotAfter, permit); got != nil {
		t.Error("anchor reused with another key")
	}
	if got, _ := ReusableAnchor(path, "a", k, ca.Root.NotAfter.Add(1), permit); got != nil {
		t.Error("anchor reused past its expiry")
	}
	if got, _ := ReusableAnchor(path, "a", k, ca.Root.NotAfter, []string{"bank.test", "other.test"}); got != nil {
		t.Error("anchor reused with another permit")
	}
}

func TestVerifyLogged(t *testing.T) {
	ca := pkitest.NewCA(t)
	leaf := ca.Leaf(t, "bank.test")
	for name, chain := range map[string][][]byte{
		"sub":      {ca.Sub.Raw},
		"sub+root": {ca.Sub.Raw, ca.Root.Raw},
	} {
		if _, err := VerifyLogged(leaf.Raw, chain, ca.Root); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	other := pkitest.NewCA(t)
	if _, err := VerifyLogged(leaf.Raw, [][]byte{ca.Sub.Raw}, other.Root); err == nil {
		t.Error("accepted a chain to another root")
	}
	if _, err := VerifyLogged(leaf.Raw, nil, ca.Root); err == nil {
		t.Error("accepted a leaf without its sub CA")
	}
	if _, err := VerifyLogged(other.Leaf(t, "bank.test").Raw, [][]byte{ca.Sub.Raw}, ca.Root); err == nil {
		t.Error("accepted a leaf not signed by the given chain")
	}
}
