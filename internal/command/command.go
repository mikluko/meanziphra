// Package command реализует подкоманды meanziphra поверх конфига.
package command

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mikluko/meanziphra/internal/anchorkey"
	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/domains"
	"github.com/mikluko/meanziphra/internal/keychain"
	"github.com/mikluko/meanziphra/internal/pki"
	"github.com/mikluko/meanziphra/internal/probe"
)

// issueRootCrosses выпускает на каждый корень один кросс-сертификат с доменами всех его непустых категорий,
// без деления на части.
func issueRootCrosses(c *config.Config, anchor *x509.Certificate, key crypto.Signer, roots map[string]*x509.Certificate, w io.Writer) error {
	for _, r := range c.Roots {
		if roots[r.Name] == nil {
			continue
		}
		var permit []string
		for _, cat := range c.Categories {
			if cat.Root == r.Name {
				permit = append(permit, cat.Permit...)
			}
		}
		slices.Sort(permit)
		permit = slices.Compact(permit)
		cross, err := pki.CrossSign(anchor, key, roots[r.Name], permit)
		if err != nil {
			return fmt.Errorf("root %s: %w", r.Name, err)
		}
		if err := pki.WriteCert(c.RootCrossPath(r), cross); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "%s: %d domains in one certificate\n", r.Name, len(permit))
	}
	return nil
}

// maxConstraints — сколько доменов несёт один кросс-сертификат. macOS отвергает сертификат,
// в name constraints которого больше 1023 записей.
const maxConstraints = 1000

// Issue пишет в каталог out якорь, ограниченный зонами доменов всех категорий, и на каждую непустую категорию
// файл с кросс-сертификатами, по maxConstraints доменов в каждом. Категория без доменов пропускается, и её
// прежний файл удаляется: кросс-сертификат с пустым permit не ограничивал бы ничего. С постоянным ключом якорь
// из out сохраняется, пока не изменился набор зон.
func Issue(c *config.Config, w io.Writer) error {
	src, err := anchorkey.ParseSource(c.Anchor.Key)
	if err != nil {
		return err
	}
	key, created, err := anchorkey.Load(src, c.Dir, c.Insecure)
	if err != nil {
		return err
	}
	if created && src.Persistent() {
		_, _ = fmt.Fprintf(w, "generated anchor key %s\n", src.Ref)
	}

	roots := map[string]*x509.Certificate{}
	var notAfter time.Time
	var permit []string
	for _, cat := range c.Categories {
		if len(cat.Permit) == 0 {
			continue
		}
		permit = append(permit, cat.Permit...)
		if roots[cat.Root] != nil {
			continue
		}
		r := c.Root(cat.Root)
		cert, err := loadRoot(c, r)
		if err != nil {
			return fmt.Errorf("root %s: %w", r.Name, err)
		}
		roots[cat.Root] = cert
		if cert.NotAfter.After(notAfter) {
			notAfter = cert.NotAfter
		}
	}
	if len(permit) == 0 {
		return errors.New("every category is empty")
	}
	permit = domains.Zones(permit)

	var anchor *x509.Certificate
	if src.Persistent() {
		if anchor, err = pki.ReusableAnchor(c.AnchorPath(), c.Anchor.Name, key, notAfter, permit); err != nil {
			return err
		}
	}
	if anchor == nil {
		if anchor, err = pki.NewAnchor(c.Anchor.Name, key, notAfter, permit); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(c.Path(c.Out), 0o755); err != nil {
		return err
	}
	if err := pki.WriteCert(c.AnchorPath(), anchor); err != nil {
		return err
	}
	if c.Target == config.TargetLinux {
		return issueRootCrosses(c, anchor, key, roots, w)
	}
	for _, cat := range c.Categories {
		path := c.CrossPath(cat)
		if len(cat.Permit) == 0 {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			_, _ = fmt.Fprintf(w, "%s: no domains, skipped\n", cat.Name)
			continue
		}
		var crosses []*x509.Certificate
		for chunk := range slices.Chunk(cat.Permit, maxConstraints) {
			cross, err := pki.CrossSign(anchor, key, roots[cat.Root], chunk)
			if err != nil {
				return fmt.Errorf("category %s: %w", cat.Name, err)
			}
			crosses = append(crosses, cross)
		}
		if err := pki.WriteCerts(path, crosses); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "%s: %d domains in %d certificates\n", cat.Name, len(cat.Permit), len(crosses))
	}
	return nil
}

// Check получает цепочку каждого хоста из check и проверяет, что выпущенные сертификаты пропускают или отвергают
// её, как задано.
func Check(ctx context.Context, c *config.Config, w io.Writer) error {
	return check(ctx, c, probe.FetchChain, w)
}

// Fetcher возвращает цепочку, которую отдаёт host.
type Fetcher func(ctx context.Context, host string) ([]*x509.Certificate, error)

type outcome int

const (
	matched outcome = iota
	mismatched
	unreachable
)

// check падает, если хоть один хост получил не тот вердикт или в категории с хостами не ответил ни один.
// Недоступный хост сам по себе только предупреждение: он ничего не говорит о выпущенных сертификатах.
func check(ctx context.Context, c *config.Config, fetch Fetcher, w io.Writer) error {
	anchor, crosses, err := loadIssued(c, nil)
	if err != nil {
		return err
	}
	var problems []string
	for _, cat := range c.Categories {
		hosts, reached := 0, 0
		for _, want := range []struct {
			hosts []string
			allow bool
		}{{cat.Check.Allow, true}, {cat.Check.Deny, false}} {
			for _, host := range want.hosts {
				hosts++
				switch checkHost(ctx, w, fetch, anchor, crosses, host, want.allow) {
				case mismatched:
					reached++
					problems = append(problems, host)
				case matched:
					reached++
				}
			}
		}
		if hosts > 0 && reached == 0 {
			problems = append(problems, "no host of "+cat.Name+" reachable")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("check failed: %s", strings.Join(problems, ", "))
	}
	return nil
}

func checkHost(ctx context.Context, w io.Writer, fetch Fetcher, anchor *x509.Certificate, crosses []*x509.Certificate, host string, wantAllow bool) outcome {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	chain, err := fetch(ctx, host)
	if err != nil {
		_, _ = fmt.Fprintf(w, "%s: unreachable, skipped (%v)\n", host, err)
		return unreachable
	}
	verr := probe.Verify(anchor, crosses, chain, host)
	allowed := verr == nil
	switch {
	case allowed == wantAllow && allowed:
		_, _ = fmt.Fprintf(w, "%s: allowed, ok\n", host)
	case allowed == wantAllow:
		_, _ = fmt.Fprintf(w, "%s: denied, ok (%v)\n", host, verr)
	case allowed:
		_, _ = fmt.Fprintf(w, "%s: allowed, want denied\n", host)
	default:
		_, _ = fmt.Fprintf(w, "%s: denied, want allowed (%v)\n", host, verr)
	}
	if allowed != wantAllow {
		return mismatched
	}
	return matched
}

// loadIssued читает якорь и кросс-сертификаты непустых категорий, а при непустом only — только перечисленных.
func loadIssued(c *config.Config, only []string) (*x509.Certificate, []*x509.Certificate, error) {
	for _, name := range only {
		if !slices.ContainsFunc(c.Categories, func(cat config.Category) bool { return cat.Name == name }) {
			return nil, nil, fmt.Errorf("unknown category %q", name)
		}
	}
	anchor, err := pki.ReadCert(c.AnchorPath())
	if err != nil {
		return nil, nil, fmt.Errorf("%w (run issue first)", err)
	}
	var crosses []*x509.Certificate
	for _, cat := range c.Categories {
		if len(cat.Permit) == 0 || (len(only) > 0 && !slices.Contains(only, cat.Name)) {
			continue
		}
		certs, err := pki.ReadCerts(c.CrossPath(cat))
		if err != nil {
			return nil, nil, fmt.Errorf("%w (run issue first)", err)
		}
		crosses = append(crosses, certs...)
	}
	return anchor, crosses, nil
}

// Install приводит наши сертификаты в связке ключей к выпущенным: якорю и кросс-сертификатам категорий only,
// а при пустом only — всех непустых категорий. Прочие наши сертификаты удаляет, неизменившийся якорь не трогает.
func Install(c *config.Config, k keychain.Keychain, only []string, w io.Writer) error {
	anchor, crosses, err := loadIssued(c, only)
	if err != nil {
		return err
	}
	installed, err := k.Owned(c.Anchor.Name)
	if err != nil {
		return err
	}
	add, remove := keychain.Plan(installed, append([]*x509.Certificate{anchor}, crosses...))
	for _, cert := range remove {
		if err := k.Remove(cert); err != nil {
			return err
		}
		report(w, "removed", cert)
	}
	for _, cert := range add {
		if err := k.Add(cert, cert.Equal(anchor)); err != nil {
			return err
		}
		report(w, "added", cert)
	}
	return nil
}

// Uninstall удаляет из связки ключей все наши сертификаты.
func Uninstall(c *config.Config, k keychain.Keychain, w io.Writer) error {
	installed, err := k.Owned(c.Anchor.Name)
	if err != nil {
		return err
	}
	for _, cert := range installed {
		if err := k.Remove(cert); err != nil {
			return err
		}
		report(w, "removed", cert)
	}
	return nil
}

func report(w io.Writer, verb string, cert *x509.Certificate) {
	_, _ = fmt.Fprintf(w, "%s %s (issuer %s)\n", verb, cert.Subject.CommonName, strings.TrimSpace(cert.Issuer.CommonName))
}

// loadRoot читает сертификат корня r из входных файлов c и сверяет его с закреплённым SHA-256.
func loadRoot(c *config.Config, r config.Root) (*x509.Certificate, error) {
	b, err := c.ReadFile(r.Cert)
	if err != nil {
		return nil, err
	}
	cert, err := pki.ParseRoot(b, r.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Cert, err)
	}
	return cert, nil
}
