package command

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/mikluko/meanziphra/internal/config"
)

// Script — данные шаблона скрипта.
type Script struct {
	Tag        string
	AnchorName string
	Categories []string
	// Sums — SHA-256 файлов, которые ставит скрипт, в формате shasum: «<hex>  <имя>».
	Sums []string
}

// Template — шаблон в FS скриптов и имя файла, в который он рендерится.
type Template struct {
	Src, Out string
}

var (
	ReleaseScripts = []Template{{"install-release.sh.tpl", "install.sh"}, {"uninstall.sh.tpl", "uninstall.sh"}}
	BundleScripts  = []Template{{"install-bundle.sh.tpl", "install.sh"}, {"uninstall.sh.tpl", "uninstall.sh"}}
)

// Sums возвращает строки shasum для files из dir.
func Sums(dir string, files []string) ([]string, error) {
	var r []string
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		r = append(r, hex.EncodeToString(sum[:])+"  "+f)
	}
	return r, nil
}

// RenderScripts рендерит tpls из fsys в каталог dir исполняемыми файлами. В шаблонах доступна функция sh,
// которая заключает строку в одинарные кавычки для bash.
func RenderScripts(fsys fs.FS, tpls []Template, dir string, s Script, w io.Writer) error {
	for _, t := range tpls {
		b, err := fs.ReadFile(fsys, t.Src)
		if err != nil {
			return err
		}
		tpl, err := template.New(t.Src).Funcs(template.FuncMap{"sh": shQuote}).Parse(string(b))
		if err != nil {
			return err
		}
		out := filepath.Join(dir, t.Out)
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if err := tpl.Execute(f, s); err != nil {
			_ = f.Close()
			return fmt.Errorf("%s: %w", t.Src, err)
		}
		if err := f.Close(); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "rendered %s\n", out)
	}
	return nil
}

// shQuote заключает s в одинарные кавычки так, что bash прочитает его буквально.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Binaries — бинарники mz, которые публикует релиз и ставит install.sh из ReleaseScripts.
var Binaries = []string{"mz-darwin-arm64", "mz-darwin-amd64"}

// RenderRelease пишет в out скрипты ReleaseScripts для релиза tag с SHA-256 бинарников Binaries,
// которые к этому моменту уже лежат в out.
func RenderRelease(c *config.Config, tag string, scripts fs.FS, w io.Writer) error {
	sums, err := Sums(c.Path(c.Out), Binaries)
	if err != nil {
		return err
	}
	s := Script{Tag: tag, AnchorName: c.Anchor.Name, Sums: sums}
	for _, cat := range c.Categories {
		s.Categories = append(s.Categories, cat.Name)
	}
	return RenderScripts(scripts, ReleaseScripts, c.Path(c.Out), s, w)
}
