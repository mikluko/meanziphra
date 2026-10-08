package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const root = "roots:\n  - {name: r, cert: r.pem, sha256: AA}\n"

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(write(t, dir, "c.yaml", root+"categories:\n  - {name: banks, root: r, permit: [a.test]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Anchor.Name != "meanziphra" || c.Out != "build" || c.Dir != dir {
		t.Errorf("defaults: %+v", c)
	}
	if got, want := c.CrossPath(c.Categories[0]), filepath.Join(dir, "build", "cat-banks.crt"); got != want {
		t.Errorf("CrossPath = %s, want %s", got, want)
	}
	if got, want := c.AnchorPath(), filepath.Join(dir, "build", "anchor.crt"); got != want {
		t.Errorf("AnchorPath = %s, want %s", got, want)
	}
	ct := "roots:\n  - {name: r, cert: r.pem, sha256: AA, ct: {logs: [x], state: s.json, tlds: [ru]}}\n"
	for name, body := range map[string]string{
		"unknown field":   root + "categories:\n  - {name: c, root: r, domains: [x]}\n",
		"no roots":        "categories:\n  - {name: c, root: r}\n",
		"no categories":   root,
		"unknown root":    root + "categories:\n  - {name: c, root: nope}\n",
		"duplicate":       root + "categories:\n  - {name: c, root: r}\n  - {name: c, root: r}\n",
		"no pin":          "roots:\n  - {name: r, cert: r.pem}\ncategories:\n  - {name: c, root: r}\n",
		"bad scheme":      "anchor: {key: 'vault://x'}\n" + root + "categories:\n  - {name: c, root: r}\n",
		"ct no classify":  ct + "categories:\n  - {name: c, root: r, description: d, permit_file: c.txt}\n",
		"described no fl": root + "categories:\n  - {name: c, root: r, description: d}\n",
	} {
		if _, err := Load(write(t, dir, "c.yaml", body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoad_PermitFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "banks.txt", "# from CT\nSberbank.ru\n\ntbank.ru\nalfabank.ru\n")
	c, err := Load(write(t, dir, "c.yaml", root+
		"categories:\n  - {name: banks, root: r, permit: [tbank.ru, extra.ru], permit_file: banks.txt}\n"+
		"  - {name: gov, root: r, permit_file: missing.txt}\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alfabank.ru", "extra.ru", "sberbank.ru", "tbank.ru"}
	if !slices.Equal(c.Categories[0].Permit, want) {
		t.Errorf("Permit = %v, want %v", c.Categories[0].Permit, want)
	}
	if len(c.Categories[1].Permit) != 0 {
		t.Errorf("missing permit_file gave %v", c.Categories[1].Permit)
	}
}

func TestReadDomains_RejectsGarbage(t *testing.T) {
	p := write(t, t.TempDir(), "d.txt", "bank.ru\nnot a domain\n")
	if _, err := ReadDomains(p); err == nil {
		t.Error("accepted a line with spaces")
	}
}

func TestWriteDomains_StableAndReadable(t *testing.T) {
	dir := t.TempDir()
	tpl := write(t, dir, "d.tpl", "# {{.Category}}\n{{range .Domains}}{{.}}\n{{end -}}\n")
	a, b := filepath.Join(dir, "a", "a.txt"), filepath.Join(dir, "b.txt")
	if err := WriteDomains(a, tpl, "banks", []string{"tbank.ru", "Sberbank.ru", "alfabank.ru", "tbank.ru"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteDomains(b, tpl, "banks", []string{"alfabank.ru", "sberbank.ru", "tbank.ru"}); err != nil {
		t.Fatal(err)
	}
	ab, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	if string(ab) != string(bb) {
		t.Errorf("same set, different files:\n%s\n%s", ab, bb)
	}
	if want := "# banks\nalfabank.ru\nsberbank.ru\ntbank.ru\n"; string(ab) != want {
		t.Errorf("rendered %q, want %q", ab, want)
	}
	got, err := ReadDomains(a)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"alfabank.ru", "sberbank.ru", "tbank.ru"}; !slices.Equal(got, want) {
		t.Errorf("round trip = %v, want %v", got, want)
	}
}

func TestWriteDomains_NeedsTemplate(t *testing.T) {
	dir := t.TempDir()
	if err := WriteDomains(filepath.Join(dir, "d.txt"), filepath.Join(dir, "none.tpl"), "c", []string{"a.ru"}); err == nil {
		t.Error("wrote without a template")
	}
}
