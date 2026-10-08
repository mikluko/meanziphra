package command

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/mikluko/meanziphra/internal/config"
)

// Script — данные шаблона скрипта релиза.
type Script struct {
	Tag        string
	AnchorName string
	// Categories — непустые категории, у которых в out есть кросс-сертификаты.
	Categories []string
	// Sums — SHA-256 выпущенных файлов в формате shasum: «<hex>  <имя>».
	Sums []string
}

// Render рендерит каждый *.tpl из dir в out под тем же именем без .tpl. Сертификаты в out к этому
// моменту уже выпущены: их SHA-256 попадают в .Sums, а в шаблоне доступна функция sh, которая
// заключает строку в одинарные кавычки для bash.
func Render(c *config.Config, dir, tag string, w io.Writer) error {
	s := Script{Tag: tag, AnchorName: c.Anchor.Name}
	files := []string{"anchor.crt"}
	for _, cat := range c.Categories {
		if len(cat.Permit) == 0 {
			continue
		}
		s.Categories = append(s.Categories, cat.Name)
		files = append(files, filepath.Base(c.CrossPath(cat)))
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(c.Path(c.Out), f))
		if err != nil {
			return fmt.Errorf("%w (run issue first)", err)
		}
		sum := sha256.Sum256(b)
		s.Sums = append(s.Sums, hex.EncodeToString(sum[:])+"  "+f)
	}

	tpls, err := filepath.Glob(filepath.Join(c.Path(dir), "*.tpl"))
	if err != nil {
		return err
	}
	if len(tpls) == 0 {
		return fmt.Errorf("no templates in %s", dir)
	}
	for _, p := range tpls {
		tpl, err := template.New(filepath.Base(p)).Funcs(template.FuncMap{"sh": shQuote}).ParseFiles(p)
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(filepath.Base(p), ".tpl")
		out := filepath.Join(c.Path(c.Out), name)
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if err := tpl.Execute(f, s); err != nil {
			_ = f.Close()
			return fmt.Errorf("%s: %w", p, err)
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
