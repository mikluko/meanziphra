// Команда mz ограничивает корень Минцифры доменами по категориям: выпускает на этом компьютере якорь
// и кросс-сертификаты с X.509 name constraints и ставит их в macOS или Linux или собирает в бандл.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/mikluko/meanziphra"
	"github.com/mikluko/meanziphra/internal/classify"
	"github.com/mikluko/meanziphra/internal/command"
	"github.com/mikluko/meanziphra/internal/config"
	"github.com/mikluko/meanziphra/internal/keychain"
	"github.com/mikluko/meanziphra/internal/memguard"
)

const usage = `usage: mz [-c config] command [flags] [args]

commands for users:
  install [-key ref] [-insecure] [-keychain path] <category>... | all
             issue the anchor and crosses on this computer and install them: into the keychain on macOS,
             into the system trust store and ~/.pki/nssdb on Linux
  bundle  [-key ref] [-insecure] [-target macos|linux|ios] -o dir <category>... | all
             issue into dir with install.sh and uninstall.sh to carry to another computer,
             or with meanziphra.mobileconfig for iOS
  uninstall [-keychain path]
             remove every certificate of this anchor from the keychain

commands for maintainers (need -c config.release.yaml):
  fetch      download each root from its url and write it to cert if it matches sha256
  update     read the roots' CT logs, classify new owners (TYPESAFE_API_KEY) and rewrite category permit_files
  issue [-insecure]
             write the anchor and constrained cross-certificates to the out directory
  check      verify configured hosts are allowed or denied by what issue wrote
  render -tag tag
             write install.sh and uninstall.sh for a release of the binaries in the out directory

Without -c, mz uses the release configuration built into it. -key takes an op:// reference, or a key file path
with -insecure; without it the anchor key is ephemeral and lives only in memory. install, bundle and issue
refuse to run unless swap is encrypted; -insecure skips that check too.

global flags:
`

func main() {
	global := flag.NewFlagSet("mz", flag.ExitOnError)
	cfgPath := global.String("c", "", "config file; empty uses the built-in release configuration")
	global.Usage = func() {
		_, _ = fmt.Fprint(global.Output(), usage)
		global.PrintDefaults()
	}
	_ = global.Parse(os.Args[1:])
	if global.NArg() < 1 {
		global.Usage()
		os.Exit(2)
	}
	if err := run(global.Arg(0), global.Args()[1:], *cfgPath, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "mz:", err)
		os.Exit(1)
	}
}

func run(cmd string, args []string, cfgPath string, w io.Writer) error {
	fl := flag.NewFlagSet("mz "+cmd, flag.ExitOnError)
	key := fl.String("key", "", "anchor key: file path or op:// reference; empty is ephemeral")
	kc := fl.String("keychain", string(keychain.Default()), "keychain for install and uninstall")
	out := fl.String("o", "", "bundle output directory")
	tag := fl.String("tag", "", "release tag written into the scripts by render")
	insecure := fl.Bool("insecure", false, "allow an anchor key file and skip the swap encryption check")
	target := fl.String("target", config.TargetMacOS, "bundle target system: macos, linux or ios")
	if err := fl.Parse(args); err != nil {
		return err
	}

	c, err := load(cfgPath)
	if err != nil {
		return err
	}
	if *key != "" {
		c.Anchor.Key = *key
		if err := c.Validate(); err != nil {
			return err
		}
	}
	c.Insecure = *insecure
	if err := memguard.NoCoreDumps(); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if handlesKey[cmd] && !*insecure {
		if err := memguard.CheckSwap(); err != nil {
			return fmt.Errorf("%w; the anchor key could reach the disk through swap, pass -insecure to run anyway", err)
		}
	}
	ctx := context.Background()

	switch cmd {
	case "install":
		if err := command.Select(c, fl.Args()); err != nil {
			return err
		}
		if runtime.GOOS == "linux" {
			return command.InstallLinux(c, meanziphra.Scripts(), w)
		}
		return command.InstallLocal(c, keychain.Keychain(*kc), w)
	case "bundle":
		if *out == "" {
			return fmt.Errorf("bundle needs -o dir")
		}
		switch *target {
		case config.TargetMacOS, config.TargetLinux, config.TargetIOS:
		default:
			return fmt.Errorf("unknown -target %q: want macos, linux or ios", *target)
		}
		if err := command.Select(c, fl.Args()); err != nil {
			return err
		}
		c.Target = *target
		return command.Bundle(c, *out, meanziphra.Scripts(), w)
	case "uninstall":
		if runtime.GOOS == "linux" {
			return command.UninstallLinux(c, meanziphra.Scripts(), w)
		}
		return command.Uninstall(c, keychain.Keychain(*kc), w)
	case "fetch":
		return command.Fetch(ctx, c, http.DefaultClient, w)
	case "update":
		var cl classify.Classifier
		if k := os.Getenv("TYPESAFE_API_KEY"); k != "" && c.Classify != nil {
			cl = command.JevClassifier(c, k)
		}
		return command.Update(ctx, c, command.CTClient(), cl, time.Now(), w)
	case "issue":
		return command.Issue(c, w)
	case "check":
		return command.Check(ctx, c, w)
	case "render":
		if *tag == "" {
			return fmt.Errorf("render needs -tag")
		}
		return command.RenderRelease(c, *tag, meanziphra.Scripts(), w)
	}
	return fmt.Errorf("unknown command %q", cmd)
}

// handlesKey — команды, которые создают или загружают ключ якоря.
var handlesKey = map[string]bool{"install": true, "bundle": true, "issue": true}

// load читает конфиг из cfgPath, а при пустом — встроенный конфиг релиза.
func load(cfgPath string) (*config.Config, error) {
	if cfgPath != "" {
		return config.Load(cfgPath)
	}
	return config.LoadFS(meanziphra.Inputs, meanziphra.ReleaseConfig, "")
}
