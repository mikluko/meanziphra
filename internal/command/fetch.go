package command

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/pki"
)

const maxRootSize = 1 << 20

// Fetch скачивает каждый корень с url и записывает его в cert в PEM, только если он совпадает с sha256.
// Корень без url пропускается; при несовпадении файл на диске не меняется.
func Fetch(ctx context.Context, c *config.Config, client *http.Client, w io.Writer) error {
	for _, r := range c.Roots {
		if r.URL == "" {
			_, _ = fmt.Fprintf(w, "%s: no url, skipped\n", r.Name)
			continue
		}
		if err := fetchRoot(ctx, client, c.Path(r.Cert), r); err != nil {
			return fmt.Errorf("root %s: %w", r.Name, err)
		}
		_, _ = fmt.Fprintf(w, "%s: %s\n", r.Name, r.Cert)
	}
	return nil
}

func fetchRoot(ctx context.Context, client *http.Client, path string, r config.Root) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", r.URL, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRootSize))
	if err != nil {
		return err
	}
	cert, err := pki.ParseCert(b)
	if err != nil {
		return fmt.Errorf("%s: %w", r.URL, err)
	}
	if err := pki.CheckPin(cert, r.SHA256); err != nil {
		return fmt.Errorf("%s: %w", r.URL, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return pki.WriteCert(path, cert)
}
