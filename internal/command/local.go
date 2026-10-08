package command

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/keychain"
)

// Select оставляет в c только категории names. Пустой names — ошибка со списком категорий,
// «all» оставляет все.
func Select(c *config.Config, names []string) error {
	var all []string
	for _, cat := range c.Categories {
		all = append(all, cat.Name)
	}
	if len(names) == 0 {
		return fmt.Errorf("name categories or all; categories: %v", all)
	}
	if slices.Contains(names, "all") {
		return nil
	}
	var kept []config.Category
	for _, n := range names {
		i := slices.Index(all, n)
		if i < 0 {
			return fmt.Errorf("unknown category %q; categories: %v", n, all)
		}
		kept = append(kept, c.Categories[i])
	}
	c.Categories = kept
	return nil
}

// Bundle выпускает в out якорь и кросс-сертификаты категорий c для c.Target и кладёт рядом install.sh
// и uninstall.sh, которые ставят и удаляют их без сети: BundleScripts для macOS, LinuxScripts для Linux.
func Bundle(c *config.Config, out string, scripts fs.FS, w io.Writer) error {
	c.Out = out
	if err := Issue(c, w); err != nil {
		return err
	}
	s := Script{AnchorName: c.Anchor.Name}
	files := []string{filepath.Base(c.AnchorPath())}
	tpls := BundleScripts
	if c.Target == config.TargetLinux {
		tpls = LinuxScripts
		for _, r := range c.Roots {
			if _, err := os.Stat(c.RootCrossPath(r)); err == nil {
				s.Crosses = append(s.Crosses, filepath.Base(c.RootCrossPath(r)))
			}
		}
		files = append(files, s.Crosses...)
	} else {
		for _, cat := range c.Categories {
			if len(cat.Permit) == 0 {
				continue
			}
			s.Categories = append(s.Categories, cat.Name)
			files = append(files, filepath.Base(c.CrossPath(cat)))
		}
	}
	sums, err := Sums(c.Path(c.Out), files)
	if err != nil {
		return err
	}
	s.Sums = sums
	return RenderScripts(scripts, tpls, c.Path(c.Out), s, w)
}

// InstallLinux собирает бандл для Linux во временный каталог и запускает его install.sh, который сам
// перезапускает себя через sudo, если запущен не от root.
func InstallLinux(c *config.Config, scripts fs.FS, w io.Writer) error {
	tmp, err := os.MkdirTemp("", "meanziphra-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	c.Target = config.TargetLinux
	if err := Bundle(c, tmp, scripts, w); err != nil {
		return err
	}
	return execScript(filepath.Join(tmp, "install.sh"), w)
}

// UninstallLinux запускает uninstall.sh из LinuxScripts.
func UninstallLinux(c *config.Config, scripts fs.FS, w io.Writer) error {
	tmp, err := os.MkdirTemp("", "meanziphra-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := RenderScripts(scripts, LinuxScripts[1:], tmp, Script{AnchorName: c.Anchor.Name}, io.Discard); err != nil {
		return err
	}
	return execScript(filepath.Join(tmp, "uninstall.sh"), w)
}

func execScript(path string, w io.Writer) error {
	cmd := exec.Command("bash", path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, w, os.Stderr
	return cmd.Run()
}

// InstallLocal выпускает якорь и кросс-сертификаты категорий c во временный каталог и ставит их в k,
// убирая прежние сертификаты этого якоря.
func InstallLocal(c *config.Config, k keychain.Keychain, w io.Writer) error {
	tmp, err := os.MkdirTemp("", "meanziphra-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	c.Out = tmp
	if err := Issue(c, w); err != nil {
		return err
	}
	return Install(c, k, nil, w)
}
