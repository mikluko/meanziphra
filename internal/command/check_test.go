package command

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/pki"
	"github.com/mikluko/meanziphra/internal/pkitest"
)

func TestCheck(t *testing.T) {
	c := issueConfig(t, "")
	ca := pkitest.NewCA(t)
	if err := pki.WriteCert(c.Path(c.Roots[0].Cert), ca.Root); err != nil {
		t.Fatal(err)
	}
	c.Roots[0].SHA256 = pki.Fingerprint(ca.Root)
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	chains := map[string][]*x509.Certificate{
		"bank.test":  {ca.Leaf(t, "bank.test"), ca.Sub},
		"other.test": {ca.Leaf(t, "other.test"), ca.Sub},
	}
	fetch := func(_ context.Context, host string) ([]*x509.Certificate, error) {
		if ch, ok := chains[host]; ok {
			return ch, nil
		}
		return nil, errors.New("i/o timeout")
	}
	for name, tc := range map[string]struct {
		check config.Check
		ok    bool
	}{
		"all as expected":        {config.Check{Allow: []string{"bank.test"}, Deny: []string{"other.test"}}, true},
		"one host unreachable":   {config.Check{Allow: []string{"bank.test", "down.test"}, Deny: []string{"other.test"}}, true},
		"wrong verdict":          {config.Check{Allow: []string{"other.test"}}, false},
		"every host unreachable": {config.Check{Allow: []string{"down.test"}, Deny: []string{"gone.test"}}, false},
		"no hosts configured":    {config.Check{}, true},
	} {
		t.Run(name, func(t *testing.T) {
			c.Categories[0].Check = tc.check
			err := check(context.Background(), c, fetch, io.Discard)
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok = %v", err, tc.ok)
			}
		})
	}
}
