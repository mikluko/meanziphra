package command

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikluko/meanziphra/internal/classify"
	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/ctlog/ctlogtest"
	"github.com/mikluko/meanziphra/internal/ctstate"
	"github.com/mikluko/meanziphra/internal/pki"
	"github.com/mikluko/meanziphra/internal/pkitest"
)

// byDomain относит владельца к banks, если в его первом домене есть «bank», иначе к other.
type byDomain struct{ calls atomic.Int32 }

func (b *byDomain) Classify(_ context.Context, s classify.Subject) (classify.Entry, error) {
	b.calls.Add(1)
	if strings.Contains(s.Domains[0], "bank") {
		return classify.Entry{Category: "banks"}, nil
	}
	return classify.Entry{Category: "other"}, nil
}

func TestUpdate(t *testing.T) {
	dir := t.TempDir()
	ca := pkitest.NewCA(t)
	if err := pki.WriteCert(filepath.Join(dir, "root.pem"), ca.Root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cat.tpl"), []byte("# {{.Category}}\n{{range .Domains}}{{.}}\n{{end -}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := ctlogtest.New(t, 2)
	log.AddCert(t, ca.Leaf(t, "bank.ru", "*.online.bank.ru").Raw, ca.Sub.Raw)
	log.AddPrecert(t, ca.Leaf(t, "shop.example.com").Raw, ca.Sub.Raw, ca.Root.Raw)
	log.AddCert(t, ca.Leaf(t, "shop.ru").Raw, ca.Sub.Raw)
	other := pkitest.NewCA(t)
	log.AddCert(t, other.Leaf(t, "evil.ru").Raw, other.Sub.Raw)

	c := &config.Config{
		Dir: dir,
		Roots: []config.Root{{
			Name: "r", Cert: "root.pem", SHA256: pki.Fingerprint(ca.Root),
			CT: &config.CT{Logs: []string{log.URL}, State: "state.json", TLDs: []string{"ru"}},
		}},
		Categories: []config.Category{
			{Name: "banks", Root: "r", Description: "banks", PermitFile: "banks.txt"},
			{Name: "other", Root: "r", Description: "other", PermitFile: "other.txt"},
		},
		Classify: &config.Classify{Cache: "cache.json", Template: "cat.tpl", Model: "m", Instructions: "?"},
	}
	cl := &byDomain{}
	run := func() (banks, rest []string) {
		t.Helper()
		if err := Update(context.Background(), c, log.Client(), cl, time.Now(), io.Discard); err != nil {
			t.Fatal(err)
		}
		var err error
		if banks, err = config.ReadDomains(filepath.Join(dir, "banks.txt")); err != nil {
			t.Fatal(err)
		}
		if rest, err = config.ReadDomains(filepath.Join(dir, "other.txt")); err != nil {
			t.Fatal(err)
		}
		return banks, rest
	}

	banks, rest := run()
	if !slices.Equal(banks, []string{"bank.ru"}) || !slices.Equal(rest, []string{"shop.ru"}) {
		t.Errorf("banks = %v, other = %v", banks, rest)
	}
	st, err := ctstate.Load(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Logs[log.URL] != 4 {
		t.Errorf("log position = %d, want 4", st.Logs[log.URL])
	}
	if _, ok := st.Names["shop.example.com"]; !ok {
		t.Error("names outside tlds are not kept in state")
	}
	if _, ok := st.Names["evil.ru"]; ok {
		t.Error("a name from a foreign root got into state")
	}
	// Без ОГРН в сертификате владелец — само имя, поэтому online.bank.ru размечается отдельно от bank.ru.
	if n := cl.calls.Load(); n != 3 {
		t.Errorf("classified %d owners, want 3", n)
	}

	read := log.Requests
	log.AddCert(t, ca.Leaf(t, "bankier.ru").Raw, ca.Sub.Raw)
	banks, _ = run()
	if want := []string{"bank.ru", "bankier.ru"}; !slices.Equal(banks, want) {
		t.Errorf("after new entry: banks = %v, want %v", banks, want)
	}
	if n := log.Requests - read; n != 1 {
		t.Errorf("second run read %d entries, want only the new one", n)
	}
	if n := cl.calls.Load(); n != 4 {
		t.Errorf("second run classified %d owners in total, want only the new one", n)
	}

	if err := Update(context.Background(), c, log.Client(), nil, time.Now(), io.Discard); err != nil {
		t.Errorf("nothing new to classify, yet no classifier failed: %v", err)
	}
	log.AddCert(t, ca.Leaf(t, "new.ru").Raw, ca.Sub.Raw)
	if err := Update(context.Background(), c, log.Client(), nil, time.Now(), io.Discard); err == nil {
		t.Error("an unclassified owner passed without a classifier")
	}
}
