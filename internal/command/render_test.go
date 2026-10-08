package command

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	c := issueConfig(t, "")
	c.Anchor.Name = "Минцифры на 'поводке'"
	if err := Issue(c, io.Discard); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(c.Dir, "scripts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tpl := "#!/usr/bin/env bash\nname={{sh .AnchorName}}\ntag={{sh .Tag}}\ncats=({{range .Categories}}{{sh .}} {{end}})\n" +
		"cat <<'S'\n{{range .Sums}}{{.}}\n{{end -}}\nS\necho \"$name|$tag|${cats[*]}\"\n"
	if err := os.WriteFile(filepath.Join(dir, "probe.sh.tpl"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Render(c, "scripts", "v1.2.3+20261008", io.Discard); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(c.Dir, "build", "probe.sh")
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Error("rendered script is not executable")
	}
	b, err := exec.Command("bash", out).Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if got, want := lines[len(lines)-1], "Минцифры на 'поводке'|v1.2.3+20261008|banks"; got != want {
		t.Errorf("script printed %q, want %q", got, want)
	}
	if len(lines) != 3 || !strings.HasSuffix(lines[0], "  anchor.crt") || !strings.HasSuffix(lines[1], "  cat-banks.crt") {
		t.Errorf("sums = %q", lines[:len(lines)-1])
	}
}
