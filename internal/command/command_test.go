package command

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/pki"
	"github.com/mikluko/meanziphra/internal/pkitest"
)

func issueConfig(t *testing.T, key string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	ca := pkitest.NewCA(t)
	if err := pki.WriteCert(filepath.Join(dir, "root.pem"), ca.Root); err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		Dir:        dir,
		Out:        "build",
		Anchor:     config.Anchor{Name: "a", Key: key},
		Roots:      []config.Root{{Name: "r", Cert: "root.pem", SHA256: pki.Fingerprint(ca.Root)}},
		Categories: []config.Category{{Name: "banks", Root: "r", Permit: []string{"bank.test"}}},
	}
}

func TestIssue_PersistentKeyKeepsAnchor(t *testing.T) {
	c := issueConfig(t, "anchor.key")
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	first, err := pki.ReadCert(c.AnchorPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	second, err := pki.ReadCert(c.AnchorPath())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Error("anchor reissued despite persistent key and unchanged permit")
	}
	if err := checkCross(c, second, 1); err != nil {
		t.Error(err)
	}
}

func TestIssue_PermitChangeReplacesAnchor(t *testing.T) {
	c := issueConfig(t, "anchor.key")
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	first, err := pki.ReadCert(c.AnchorPath())
	if err != nil {
		t.Fatal(err)
	}
	c.Categories[0].Permit = []string{"bank.test", "other.test"}
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	second, err := pki.ReadCert(c.AnchorPath())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Error("anchor replaced although the zones did not change")
	}
	if err := checkCross(c, second, 2); err != nil {
		t.Error(err)
	}
	c.Categories[0].Permit = []string{"bank.test", "bank.example"}
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	third, err := pki.ReadCert(c.AnchorPath())
	if err != nil {
		t.Fatal(err)
	}
	if second.Equal(third) {
		t.Error("anchor kept although a zone was added")
	}
	if got := third.PermittedDNSDomains; !slices.Equal(got, []string{"example", "test"}) {
		t.Errorf("anchor permitted = %v, want the zones", got)
	}
}

func checkCross(c *config.Config, anchor *x509.Certificate, permitted int) error {
	cross, err := pki.ReadCert(c.CrossPath(c.Categories[0]))
	if err != nil {
		return err
	}
	if len(cross.PermittedDNSDomains) != permitted {
		return fmt.Errorf("cross permitted = %v, want %d names", cross.PermittedDNSDomains, permitted)
	}
	if err := cross.CheckSignatureFrom(anchor); err != nil {
		return fmt.Errorf("cross not signed by anchor: %w", err)
	}
	return nil
}

func TestIssue_EphemeralKeyReplacesAnchor(t *testing.T) {
	c := issueConfig(t, "")
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	first, err := pki.ReadCert(c.AnchorPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	second, err := pki.ReadCert(c.AnchorPath())
	if err != nil {
		t.Fatal(err)
	}
	if first.Equal(second) {
		t.Error("ephemeral key reused the anchor")
	}
}

func TestIssue_RejectsWrongPin(t *testing.T) {
	c := issueConfig(t, "")
	c.Roots[0].SHA256 = "00"
	if err := Issue(c, io.Discard); err == nil {
		t.Error("issued under a root that fails its pin")
	}
}

func TestIssue_EmptyCategoryIsSkipped(t *testing.T) {
	c := issueConfig(t, "")
	c.Categories = append(c.Categories, config.Category{Name: "gov", Root: "r"})
	stale := c.CrossPath(c.Categories[1])
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("empty category left %s behind: %v", stale, err)
	}
	c.Categories[0].Permit = nil
	if err := Issue(c, io.Discard); err == nil {
		t.Error("issued with every category empty")
	}
}

func TestLoadIssued_Only(t *testing.T) {
	c := issueConfig(t, "")
	c.Categories = append(c.Categories, config.Category{Name: "gov", Root: "r", Permit: []string{"gov.test"}})
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	_, all, err := loadIssued(c, nil)
	if err != nil || len(all) != 2 {
		t.Fatalf("all: %d crosses, %v", len(all), err)
	}
	_, one, err := loadIssued(c, []string{"gov"})
	if err != nil || len(one) != 1 || one[0].PermittedDNSDomains[0] != "gov.test" {
		t.Fatalf("only gov: %v, %v", one, err)
	}
	if _, _, err := loadIssued(c, []string{"nope"}); err == nil {
		t.Error("unknown category accepted")
	}
}

func TestIssue_ChunksLargeCategories(t *testing.T) {
	c := issueConfig(t, "")
	var permit []string
	for i := range 2*maxConstraints + 1 {
		permit = append(permit, fmt.Sprintf("d%04d.test", i))
	}
	c.Categories[0].Permit = permit
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	crosses, err := pki.ReadCerts(c.CrossPath(c.Categories[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(crosses) != 3 {
		t.Fatalf("%d crosses, want 3", len(crosses))
	}
	var got []string
	for _, x := range crosses {
		if n := len(x.PermittedDNSDomains); n > maxConstraints {
			t.Errorf("cross carries %d constraints", n)
		}
		got = append(got, x.PermittedDNSDomains...)
	}
	if !slices.Equal(got, permit) {
		t.Error("chunks do not add up to the category")
	}
}
