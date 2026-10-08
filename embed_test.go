package meanziphra

import (
	"io"
	"io/fs"
	"testing"

	"github.com/mikluko/meanziphra/internal/command"
	"github.com/mikluko/meanziphra/internal/config"
)

func TestInputsCarryTheReleaseConfig(t *testing.T) {
	c, err := config.LoadFS(Inputs, ReleaseConfig, "")
	if err != nil {
		t.Fatal(err)
	}
	empty := 0
	for _, cat := range c.Categories {
		if len(cat.Permit) == 0 {
			empty++
		}
	}
	if empty == len(c.Categories) {
		t.Fatal("no category domains embedded")
	}
	c.Out = t.TempDir()
	if err := command.Issue(c, io.Discard); err != nil {
		t.Fatalf("issue from the embedded inputs: %v", err)
	}
}

func TestScriptsCarryEveryTemplate(t *testing.T) {
	for _, set := range [][]command.Template{command.ReleaseScripts, command.BundleScripts} {
		for _, tpl := range set {
			if _, err := fs.Stat(Scripts(), tpl.Src); err != nil {
				t.Errorf("%s: %v", tpl.Src, err)
			}
		}
	}
}
