package command

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/pki"
	"github.com/mikluko/meanziphra/internal/pkitest"
)

func TestFetch(t *testing.T) {
	ca := pkitest.NewCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/root.cer":
			_, _ = w.Write(ca.Root.Raw)
		case "/root.pem":
			_, _ = w.Write(pki.EncodePEM(ca.Root))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	for _, path := range []string{"/root.cer", "/root.pem"} {
		t.Run(path, func(t *testing.T) {
			c := &config.Config{Dir: t.TempDir(), Roots: []config.Root{{
				Name: "r", Cert: "inputs/r.pem", URL: srv.URL + path, SHA256: pki.Fingerprint(ca.Root),
			}}}
			if err := Fetch(context.Background(), c, srv.Client(), io.Discard); err != nil {
				t.Fatal(err)
			}
			got, err := pki.ReadCert(filepath.Join(c.Dir, "inputs/r.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(ca.Root) {
				t.Error("written certificate differs from the served one")
			}
		})
	}

	t.Run("pin mismatch leaves the file alone", func(t *testing.T) {
		c := &config.Config{Dir: t.TempDir(), Roots: []config.Root{{
			Name: "r", Cert: "r.pem", URL: srv.URL + "/root.cer", SHA256: "00",
		}}}
		if err := Fetch(context.Background(), c, srv.Client(), io.Discard); err == nil {
			t.Fatal("accepted a root that fails its pin")
		}
		if _, err := os.Stat(filepath.Join(c.Dir, "r.pem")); !os.IsNotExist(err) {
			t.Errorf("file written despite pin mismatch: %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		c := &config.Config{Dir: t.TempDir(), Roots: []config.Root{{
			Name: "r", Cert: "r.pem", URL: srv.URL + "/missing", SHA256: pki.Fingerprint(ca.Root),
		}}}
		if err := Fetch(context.Background(), c, srv.Client(), io.Discard); err == nil {
			t.Fatal("404 accepted")
		}
	})

	t.Run("no url is skipped", func(t *testing.T) {
		c := &config.Config{Dir: t.TempDir(), Roots: []config.Root{{Name: "r", Cert: "r.pem", SHA256: "00"}}}
		if err := Fetch(context.Background(), c, srv.Client(), io.Discard); err != nil {
			t.Fatal(err)
		}
	})
}
