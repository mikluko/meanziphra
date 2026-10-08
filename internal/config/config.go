// Package config читает конфиг meanziphra.
package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	"go.yaml.in/yaml/v3"

	"github.com/mikluko/meanziphra/internal/anchorkey"
)

type Config struct {
	Anchor     Anchor     `yaml:"anchor"`
	Out        string     `yaml:"out"`
	Roots      []Root     `yaml:"roots"`
	Categories []Category `yaml:"categories"`
	// Classify — как update раскладывает имена из CT по категориям.
	Classify *Classify `yaml:"classify"`

	// Dir — каталог, от которого отсчитываются относительные пути для записи.
	Dir string `yaml:"-"`
	// FS — откуда читаются входные файлы конфига: корни, permit_file, шаблоны.
	FS fs.FS `yaml:"-"`
	// Insecure разрешает держать ключ якоря в файле.
	Insecure bool `yaml:"-"`
	// Target — для какой системы выпускаются кросс-сертификаты: TargetMacOS, TargetLinux или TargetIOS.
	Target string `yaml:"-"`
}

type Anchor struct {
	// Name — CN якоря; по нему install и uninstall узнают свои сертификаты.
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

// Root — чужой корневой УЦ, который ограничивается.
type Root struct {
	Name string `yaml:"name"`
	Cert string `yaml:"cert"`
	// URL — откуда fetch скачивает Cert.
	URL    string `yaml:"url"`
	SHA256 string `yaml:"sha256"`
	// CT — журналы, из которых update берёт имена сертификатов этого корня.
	CT *CT `yaml:"ct"`
}

type CT struct {
	// Logs — базовые URL журналов RFC 6962.
	Logs []string `yaml:"logs"`
	// State — файл, где update хранит прочитанные позиции журналов и найденные имена.
	State string `yaml:"state"`
	// TLDs — зоны, имена в которых раскладываются по категориям; остальные только считаются.
	TLDs []string `yaml:"tlds"`
}

// Category — набор доменов, которым ограничен корень Root; issue выпускает на неё свой кросс-сертификат.
type Category struct {
	Name string `yaml:"name"`
	Root string `yaml:"root"`
	// Description — что входит в категорию. Категория с описанием участвует в классификации,
	// и update переписывает её PermitFile.
	Description string   `yaml:"description"`
	Permit      []string `yaml:"permit"`
	// PermitFile — файл с доменами по одному в строке; Load дописывает их в Permit.
	PermitFile string `yaml:"permit_file"`
	Check      Check  `yaml:"check"`
}

type Check struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type Classify struct {
	// Cache — файл с категориями владельцев сертификатов; update дописывает туда новых.
	Cache string `yaml:"cache"`
	// Template — шаблон text/template для PermitFile категорий; получает .Category и .Domains.
	Template string `yaml:"template"`
	// Model — модель TypeSafe.
	Model string `yaml:"model"`
	// Instructions — вопрос классификатору; строка или структура, уходит в Jev как есть.
	Instructions any `yaml:"instructions"`
	// MinConfidence — ответ с меньшей уверенностью помечается для проверки человеком.
	MinConfidence float64 `yaml:"min_confidence"`
}

// Load читает конфиг из файла path; входные файлы читаются из его каталога, туда же пишется вывод.
func Load(path string) (*Config, error) {
	dir := filepath.Dir(path)
	return LoadFS(os.DirFS(dir), filepath.Base(path), dir)
}

// LoadFS читает конфиг name из fsys и отвергает неизвестные поля. Входные файлы читаются из fsys,
// а относительные пути для записи отсчитываются от dir. Домены из permit_file дописываются в Permit,
// повторы удаляются; отсутствующий permit_file пуст.
func LoadFS(fsys fs.FS, name, dir string) (*Config, error) {
	path := filepath.Join(dir, name)
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Dir = dir
	c.FS = fsys
	if c.Anchor.Name == "" {
		c.Anchor.Name = "meanziphra"
	}
	if c.Out == "" {
		c.Out = "build"
	}
	for i := range c.Categories {
		cat := &c.Categories[i]
		if cat.PermitFile == "" {
			continue
		}
		b, err := c.ReadFile(cat.PermitFile)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("category %s: %w", cat.Name, err)
		}
		domains, err := ParseDomains(cat.PermitFile, b)
		if err != nil {
			return nil, fmt.Errorf("category %s: %w", cat.Name, err)
		}
		cat.Permit = append(cat.Permit, domains...)
		slices.Sort(cat.Permit)
		cat.Permit = slices.Compact(cat.Permit)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if _, err := anchorkey.ParseSource(c.Anchor.Key); err != nil {
		return err
	}
	if len(c.Roots) == 0 {
		return errors.New("no roots")
	}
	roots := map[string]bool{}
	ct := false
	for i, r := range c.Roots {
		switch {
		case r.Name == "":
			return fmt.Errorf("roots[%d]: no name", i)
		case roots[r.Name]:
			return fmt.Errorf("roots[%d]: duplicate name %q", i, r.Name)
		case r.Cert == "":
			return fmt.Errorf("root %s: no cert", r.Name)
		case r.SHA256 == "":
			return fmt.Errorf("root %s: no sha256", r.Name)
		case r.CT != nil && (len(r.CT.Logs) == 0 || r.CT.State == "" || len(r.CT.TLDs) == 0):
			return fmt.Errorf("root %s: ct needs logs, state and tlds", r.Name)
		}
		roots[r.Name] = true
		ct = ct || r.CT != nil
	}
	if len(c.Categories) == 0 {
		return errors.New("no categories")
	}
	cats := map[string]bool{}
	classified := false
	for i, cat := range c.Categories {
		switch {
		case cat.Name == "":
			return fmt.Errorf("categories[%d]: no name", i)
		case cats[cat.Name]:
			return fmt.Errorf("categories[%d]: duplicate name %q", i, cat.Name)
		case !roots[cat.Root]:
			return fmt.Errorf("category %s: unknown root %q", cat.Name, cat.Root)
		case cat.Description != "" && cat.PermitFile == "":
			return fmt.Errorf("category %s: description needs permit_file for update to write", cat.Name)
		}
		cats[cat.Name] = true
		classified = classified || cat.Description != ""
	}
	if ct && (c.Classify == nil || c.Classify.Cache == "" || c.Classify.Template == "" || c.Classify.Model == "" || c.Classify.Instructions == nil || !classified) {
		return errors.New("ct needs classify with cache, template, model and instructions, and categories with a description")
	}
	return nil
}

// Root возвращает корень с именем name.
func (c *Config) Root(name string) Root {
	for _, r := range c.Roots {
		if r.Name == name {
			return r
		}
	}
	return Root{}
}

// ReadFile читает входной файл p: абсолютный путь — с диска, относительный — из FS, а без FS — от Dir.
func (c *Config) ReadFile(p string) ([]byte, error) {
	if filepath.IsAbs(p) || c.FS == nil {
		return os.ReadFile(c.Path(p))
	}
	return fs.ReadFile(c.FS, filepath.ToSlash(filepath.Clean(p)))
}

// ReadDomains читает домены из файла path, как ParseDomains.
func ReadDomains(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseDomains(path, b)
}

// ParseDomains разбирает домены по одному в строке; name нужен для сообщений об ошибках.
// Пустые строки и строки, начинающиеся с #, пропускаются.
func ParseDomains(name string, b []byte) ([]string, error) {
	var domains []string
	path := name
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, " \t") {
			return nil, fmt.Errorf("%s:%d: %q is not a domain", path, n, line)
		}
		domains = append(domains, strings.ToLower(line))
	}
	return domains, sc.Err()
}

// WriteDomains пишет в path шаблон tplText (text/template), передавая category в .Category, а domains
// в .Domains в нижнем регистре, по алфавиту и без повторов: один и тот же набор всегда даёт один и тот же файл.
func WriteDomains(path, tplText, category string, domains []string) error {
	tpl, err := template.New(filepath.Base(path)).Parse(tplText)
	if err != nil {
		return err
	}
	sorted := make([]string, len(domains))
	for i, d := range domains {
		sorted[i] = strings.ToLower(d)
	}
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	var b bytes.Buffer
	data := struct {
		Category string
		Domains  []string
	}{category, sorted}
	if err := tpl.Execute(&b, data); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

// Path отсчитывает относительный p от Dir.
func (c *Config) Path(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Dir, p)
}

const (
	// TargetMacOS — кросс-сертификаты по категориям: macOS сам выбирает из нескольких на один корень.
	TargetMacOS = "macos"
	// TargetLinux — один кросс-сертификат на корень: OpenSSL из нескольких берёт первый и других не пробует.
	TargetLinux = "linux"
	// TargetIOS — кросс-сертификаты как для macOS, упакованные в профиль конфигурации.
	TargetIOS = "ios"
)

func (c *Config) AnchorPath() string {
	return filepath.Join(c.Path(c.Out), "anchor.crt")
}

func (c *Config) CrossPath(cat Category) string {
	return filepath.Join(c.Path(c.Out), "cat-"+cat.Name+".crt")
}

// RootCrossPath — файл единственного кросс-сертификата корня r для TargetLinux.
func (c *Config) RootCrossPath(r Root) string {
	return filepath.Join(c.Path(c.Out), "cross-"+r.Name+".crt")
}
