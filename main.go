// Команда meanziphra ограничивает чужой корневой УЦ списком доменов: перевыпускает корень от имени локального якоря
// с X.509 name constraints, так что доверенным становится только якорь, а цепочки корня несут ограничение.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mikluko/meanziphra/internal/classify"
	"github.com/mikluko/meanziphra/internal/command"
	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/keychain"
)

const usage = `usage: meanziphra [-c config] [-keychain path] [-only categories] command

commands:
  fetch      download each root from its url and write it to cert if it matches sha256
  update     read the roots' CT logs, classify new owners (TYPESAFE_API_KEY) and rewrite category permit_files
  issue      write the anchor and constrained cross-certificates to the out directory
  render     write install.sh and uninstall.sh for a release from scripts/*.tpl into the out directory
  check      verify configured hosts are allowed or denied by what issue wrote
  install    put the issued certificates into the keychain, replacing earlier ones
  uninstall  remove every certificate of this anchor from the keychain

flags:
`

func main() {
	cfgPath := flag.String("c", "config.release.yaml", "config file")
	kc := flag.String("keychain", string(keychain.Default()), "keychain for install and uninstall")
	only := flag.String("only", "", "comma-separated categories for install; empty installs all")
	tag := flag.String("tag", "", "release tag written into the scripts by render")
	flag.Usage = func() {
		_, _ = fmt.Fprint(flag.CommandLine.Output(), usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(flag.Arg(0), *cfgPath, keychain.Keychain(*kc), *only, *tag); err != nil {
		fmt.Fprintln(os.Stderr, "meanziphra:", err)
		os.Exit(1)
	}
}

func run(cmd, cfgPath string, kc keychain.Keychain, only, tag string) error {
	c, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	switch cmd {
	case "fetch":
		return command.Fetch(context.Background(), c, http.DefaultClient, os.Stdout)
	case "update":
		var cl classify.Classifier
		if key := os.Getenv("TYPESAFE_API_KEY"); key != "" && c.Classify != nil {
			cl = command.JevClassifier(c, key)
		}
		return command.Update(context.Background(), c, command.CTClient(), cl, time.Now(), os.Stdout)
	case "issue":
		return command.Issue(c, os.Stdout)
	case "render":
		if tag == "" {
			return fmt.Errorf("render needs -tag")
		}
		return command.Render(c, "scripts", tag, os.Stdout)
	case "check":
		return command.Check(context.Background(), c, os.Stdout)
	case "install":
		var cats []string
		if only != "" {
			cats = strings.Split(only, ",")
		}
		return command.Install(c, kc, cats, os.Stdout)
	case "uninstall":
		return command.Uninstall(c, kc, os.Stdout)
	}
	return fmt.Errorf("unknown command %q", cmd)
}
