package command

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/mikluko/meanziphra/internal/classify"
	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/ctlog"
	"github.com/mikluko/meanziphra/internal/ctstate"
	"github.com/mikluko/meanziphra/internal/domains"
	"github.com/mikluko/meanziphra/internal/jev"
	"github.com/mikluko/meanziphra/internal/pki"
)

// classifyWorkers — сколько запросов к классификатору идут одновременно.
const classifyWorkers = 8

// subjectDomains — сколько доменов владельца получает классификатор.
const subjectDomains = 10

// CTClient — HTTP-клиент для журналов CT. TLS-сертификат журнала не проверяется: журналы digital.gov.ru
// подписаны НУЦ без промежуточного в цепочке, а подлинность каждой записи update проверяет сам, по цепочке
// до закреплённого корня. Подменить запись в пути нельзя; утаить можно, и тогда домен просто не попадёт в список.
func CTClient() *http.Client {
	return &http.Client{
		Timeout:   2 * time.Minute,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

// JevClassifier размечает владельцев моделью из c.Classify, предлагая категории с описанием.
func JevClassifier(c *config.Config, apiKey string) classify.Classifier {
	return &classify.Jev{
		Client: &jev.Client{
			URL: jev.DefaultURL, APIKey: apiKey, Model: c.Classify.Model,
			HTTP: &http.Client{Timeout: time.Minute}, Retries: 5, Backoff: time.Second,
		},
		Instructions:  c.Classify.Instructions,
		Criteria:      criteria(c),
		MinConfidence: c.Classify.MinConfidence,
	}
}

func criteria(c *config.Config) map[string]string {
	m := map[string]string{}
	for _, cat := range c.Categories {
		if cat.Description != "" {
			m[cat.Name] = cat.Description
		}
	}
	return m
}

// fingerprint меняется вместе с моделью, инструкциями или категориями, и тогда кэш разметки сбрасывается.
func fingerprint(c *config.Config) (string, error) {
	b, err := json.Marshal(struct {
		Model        string
		Instructions any
		Criteria     map[string]string
	}{c.Classify.Model, c.Classify.Instructions, criteria(c)})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Update дочитывает журналы CT корней с секцией ct, запоминает имена из сертификатов этих корней и забывает
// истёкшие на now. Владельцев новых имён из зон ct.tlds размечает cl, после чего переписывает permit_file каждой
// категории с описанием: её имена без тех, что уже покрыты своим предком. Без cl падает, если размечать есть кого.
func Update(ctx context.Context, c *config.Config, hc *http.Client, cl classify.Classifier, now time.Time, w io.Writer) error {
	subjects := map[string]classify.Subject{}
	names := map[string][]string{}
	keyRoot := map[string]string{}
	for _, r := range c.Roots {
		if r.CT == nil {
			continue
		}
		st, err := readRoot(ctx, c, r, hc, now, w)
		if err != nil {
			return fmt.Errorf("root %s: %w", r.Name, err)
		}
		for _, n := range st.Valid() {
			if !slices.Contains(r.CT.TLDs, domains.TLD(n)) {
				continue
			}
			owner := st.Names[n].Owner
			k := classify.Key(n, owner)
			s := subjects[k]
			s.Org, s.INN, s.OGRN = owner.Org, owner.INN, owner.OGRN
			s.Domains = append(s.Domains, n)
			subjects[k] = s
			names[k] = append(names[k], n)
			keyRoot[k] = r.Name
		}
	}
	for k, s := range subjects {
		s.Domains = domains.Minimize(s.Domains)
		s.Domains = s.Domains[:min(len(s.Domains), subjectDomains)]
		subjects[k] = s
	}

	fp, err := fingerprint(c)
	if err != nil {
		return err
	}
	cachePath := c.Path(c.Classify.Cache)
	cache, err := classify.Load(cachePath, fp)
	if err != nil {
		return err
	}
	cache.Retain(subjects)
	missing := len(subjects) - len(cache.Entries)
	if missing > 0 && cl == nil {
		return fmt.Errorf("%d owners need classification and no classifier is configured", missing)
	}
	if missing > 0 {
		n, err := classify.Fill(ctx, cache, subjects, cl, classifyWorkers)
		if saveErr := cache.Save(cachePath); saveErr != nil && err == nil {
			err = saveErr
		}
		if err != nil {
			return fmt.Errorf("classify: %w", err)
		}
		_, _ = fmt.Fprintf(w, "classified %d new owners\n", n)
	}
	if err := cache.Save(cachePath); err != nil {
		return err
	}

	tpl, err := c.ReadFile(c.Classify.Template)
	if err != nil {
		return err
	}
	for _, cat := range c.Categories {
		if cat.Description == "" {
			continue
		}
		var list []string
		review := 0
		for k, e := range cache.Entries {
			if e.Category != cat.Name || keyRoot[k] != cat.Root {
				continue
			}
			list = append(list, names[k]...)
			if e.Review {
				review++
			}
		}
		list = domains.Minimize(list)
		if err := config.WriteDomains(c.Path(cat.PermitFile), string(tpl), cat.Name, list); err != nil {
			return fmt.Errorf("category %s: %w", cat.Name, err)
		}
		_, _ = fmt.Fprintf(w, "%s: %d domains, %d owners to review\n", cat.Name, len(list), review)
	}
	return nil
}

func readRoot(ctx context.Context, c *config.Config, r config.Root, hc *http.Client, now time.Time, w io.Writer) (*ctstate.State, error) {
	root, err := loadRoot(c, r)
	if err != nil {
		return nil, err
	}
	statePath := c.Path(r.CT.State)
	st, err := ctstate.Load(statePath)
	if err != nil {
		return nil, err
	}
	for _, url := range r.CT.Logs {
		if err := readLog(ctx, url, hc, root, st, w); err != nil {
			return nil, fmt.Errorf("%s: %w", url, err)
		}
	}
	st.Prune(now)
	if err := st.Save(statePath); err != nil {
		return nil, err
	}
	excluded := map[string]int{}
	for _, n := range st.Valid() {
		if tld := domains.TLD(n); !slices.Contains(r.CT.TLDs, tld) {
			excluded[tld]++
		}
	}
	_, _ = fmt.Fprintf(w, "%s: %d valid names, outside %v: %v\n", r.Name, len(st.Names), r.CT.TLDs, excluded)
	return st, nil
}

func readLog(ctx context.Context, url string, hc *http.Client, root *x509.Certificate, st *ctstate.State, w io.Writer) error {
	l, err := ctlog.New(url, hc)
	if err != nil {
		return err
	}
	size, err := l.Size(ctx)
	if err != nil {
		return err
	}
	from := st.Logs[url]
	if size < from {
		return fmt.Errorf("log shrank from %d to %d entries", from, size)
	}
	var added, broken, foreign int
	err = l.Entries(ctx, from, size, func(e ctlog.Entry, err error) error {
		if err != nil {
			broken++
			return nil
		}
		cert, err := pki.VerifyLogged(e.Cert, e.Chain, root)
		if err != nil {
			foreign++
			return nil
		}
		owner := ctstate.OwnerOf(cert)
		for _, name := range cert.DNSNames {
			if n, ok := domains.Normalize(name); ok {
				st.Add(n, cert.NotAfter, owner)
			}
		}
		added++
		return nil
	})
	if err != nil {
		return err
	}
	st.Logs[url] = size
	_, _ = fmt.Fprintf(w, "%s: entries %d..%d, %d under root, %d not under root, %d unparsable\n",
		url, from, size, added, foreign, broken)
	return nil
}
