package command

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/pki"
)

const probeTpl = "#!/usr/bin/env bash\nname={{sh .AnchorName}}\ntag={{sh .Tag}}\ncats=({{range .Categories}}{{sh .}} {{end}})\n" +
	"cat <<'S'\n{{range .Sums}}{{.}}\n{{end -}}\nS\necho \"$name|$tag|${cats[*]}\"\n"

func runScript(t *testing.T, path string) []string {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("%s is not executable", path)
	}
	b, err := exec.Command("bash", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestBundle(t *testing.T) {
	c := issueConfig(t, "")
	c.Anchor.Name = "Минцифры на 'поводке'"
	scripts := fstest.MapFS{
		"install-bundle.sh.tpl": {Data: []byte(probeTpl)},
		"uninstall.sh.tpl":      {Data: []byte("#!/usr/bin/env bash\necho {{sh .AnchorName}}\n")},
	}
	out := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Bundle(c, out, scripts, io.Discard); err != nil {
		t.Fatal(err)
	}
	lines := runScript(t, filepath.Join(out, "install.sh"))
	if got, want := lines[len(lines)-1], "Минцифры на 'поводке'||banks"; got != want {
		t.Errorf("install.sh printed %q, want %q", got, want)
	}
	if len(lines) != 3 || !strings.HasSuffix(lines[0], "  anchor.crt") || !strings.HasSuffix(lines[1], "  cat-banks.crt") {
		t.Errorf("sums = %q", lines[:len(lines)-1])
	}
	if _, err := pki.ReadCert(filepath.Join(out, "anchor.crt")); err != nil {
		t.Error(err)
	}
	if got := runScript(t, filepath.Join(out, "uninstall.sh")); got[0] != c.Anchor.Name {
		t.Errorf("uninstall.sh printed %q", got)
	}
}

func TestRenderRelease(t *testing.T) {
	c := issueConfig(t, "")
	dir := c.Path(c.Out)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, b := range Binaries {
		if err := os.WriteFile(filepath.Join(dir, b), []byte(b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	scripts := fstest.MapFS{
		"install-release.sh.tpl": {Data: []byte(probeTpl)},
		"uninstall.sh.tpl":       {Data: []byte("#!/usr/bin/env bash\n")},
	}
	if err := RenderRelease(c, "v1.2.3", scripts, io.Discard); err != nil {
		t.Fatal(err)
	}
	lines := runScript(t, filepath.Join(dir, "install.sh"))
	if got, want := lines[len(lines)-1], "a|v1.2.3|banks"; got != want {
		t.Errorf("install.sh printed %q, want %q", got, want)
	}
	if !strings.HasSuffix(lines[0], "  mz-darwin-arm64") || !strings.HasSuffix(lines[1], "  mz-darwin-amd64") {
		t.Errorf("sums = %q", lines[:2])
	}
}

func TestSelect(t *testing.T) {
	mk := func() *config.Config {
		return &config.Config{Categories: []config.Category{{Name: "banks"}, {Name: "gov"}, {Name: "other"}}}
	}
	names := func(c *config.Config) []string {
		var r []string
		for _, cat := range c.Categories {
			r = append(r, cat.Name)
		}
		return r
	}
	c := mk()
	if err := Select(c, []string{"other", "banks"}); err != nil || !slices.Equal(names(c), []string{"other", "banks"}) {
		t.Errorf("Select = %v, %v", names(c), err)
	}
	c = mk()
	if err := Select(c, []string{"all"}); err != nil || len(c.Categories) != 3 {
		t.Errorf("all = %v, %v", names(c), err)
	}
	if err := Select(mk(), nil); err == nil {
		t.Error("no categories accepted")
	}
	if err := Select(mk(), []string{"nope"}); err == nil {
		t.Error("unknown category accepted")
	}
}
