// Package classify раскладывает владельцев сертификатов по категориям и хранит разметку в кэше.
package classify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"slices"
	"sync"

	"github.com/mikluko/meanziphra/internal/ctstate"
	"github.com/mikluko/meanziphra/internal/jev"
)

// Subject — то, что классификатор знает о владельце: реквизиты из сертификата и несколько его доменов.
type Subject struct {
	Org     string   `json:"organization,omitempty"`
	INN     string   `json:"inn,omitempty"`
	OGRN    string   `json:"ogrn,omitempty"`
	Domains []string `json:"domains"`
}

type Entry struct {
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	// Review — уверенность ниже порога, разметку стоит проверить человеку.
	Review bool   `json:"review,omitempty"`
	Org    string `json:"org,omitempty"`
}

type Cache struct {
	// Fingerprint — отпечаток модели, инструкций и категорий, по которым размечены Entries.
	Fingerprint string           `json:"fingerprint"`
	Entries     map[string]Entry `json:"entries"`
}

// Key возвращает ключ владельца имени: ОГРН, если он есть в сертификате, иначе само имя.
func Key(name string, o ctstate.Owner) string {
	if o.OGRN != "" {
		return "ogrn:" + o.OGRN
	}
	return "name:" + name
}

// Load читает кэш из path. Отсутствующий файл или другой fingerprint дают пустой кэш с fingerprint.
func Load(path, fingerprint string) (*Cache, error) {
	empty := &Cache{Fingerprint: fingerprint, Entries: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return nil, err
	}
	var c Cache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Fingerprint != fingerprint || c.Entries == nil {
		return empty, nil
	}
	return &c, nil
}

// Save пишет кэш с ключами по алфавиту, по одному на строку.
func (c *Cache) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Retain удаляет записи, ключей которых нет в keys.
func (c *Cache) Retain(keys map[string]Subject) {
	for k := range c.Entries {
		if _, ok := keys[k]; !ok {
			delete(c.Entries, k)
		}
	}
}

type Classifier interface {
	Classify(ctx context.Context, s Subject) (Entry, error)
}

// Fill размечает subjects, которых ещё нет в кэше, держа не больше workers запросов одновременно.
// Первая ошибка останавливает разметку; уже полученные ответы остаются в кэше.
func Fill(ctx context.Context, c *Cache, subjects map[string]Subject, cl Classifier, workers int) (int, error) {
	var todo []string
	for k := range subjects {
		if _, ok := c.Entries[k]; !ok {
			todo = append(todo, k)
		}
	}
	slices.Sort(todo)
	if len(todo) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
		keys     = make(chan string)
	)
	for range max(workers, 1) {
		wg.Go(func() {
			for k := range keys {
				e, err := cl.Classify(ctx, subjects[k])
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", k, err)
					cancel()
				} else if err == nil {
					c.Entries[k] = e
				}
				mu.Unlock()
			}
		})
	}
	sent := 0
	for _, k := range todo {
		select {
		case keys <- k:
			sent++
			continue
		case <-ctx.Done():
		}
		break
	}
	close(keys)
	wg.Wait()
	return sent, firstErr
}

// Jev размечает владельца одним вопросом Choice: категории — это ключи Criteria, их описания — значения.
type Jev struct {
	Client        *jev.Client
	Instructions  any
	Criteria      map[string]string
	MinConfidence float64
}

func (j *Jev) Classify(ctx context.Context, s Subject) (Entry, error) {
	resp, err := j.Client.Ask(ctx, s, map[string]jev.Question{
		"category": {Type: "choice", Instructions: j.Instructions, Criteria: j.Criteria},
	})
	if err != nil {
		return Entry{}, err
	}
	a, ok := resp.Answers["category"]
	if !ok {
		return Entry{}, errors.New("no answer to category")
	}
	if _, ok := j.Criteria[a.Choice]; !ok {
		return Entry{}, fmt.Errorf("answer %q is not a category", a.Choice)
	}
	return Entry{
		Category:   a.Choice,
		Confidence: math.Round(a.Confidence*1000) / 1000,
		Review:     a.Confidence < j.MinConfidence,
		Org:        s.Org,
	}, nil
}
