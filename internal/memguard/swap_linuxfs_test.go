package memguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// sysfs строит поддельное дерево sysfs: devices — каталоги устройств с dm/uuid, slaves и partition,
// а dev/block/MAJ:MIN — ссылки на них, как в настоящем /sys.
type sysfs struct {
	t    *testing.T
	root string
}

func newSysfs(t *testing.T) *sysfs {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dev", "block"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &sysfs{t: t, root: root}
}

// dev заводит устройство name с номером majMin; uuid пишется в dm/uuid, slaves — нижележащие устройства.
func (s *sysfs) dev(name, majMin, uuid string, slaves ...string) string {
	s.t.Helper()
	dir := filepath.Join(s.root, "devices", name)
	if err := os.MkdirAll(filepath.Join(dir, "slaves"), 0o755); err != nil {
		s.t.Fatal(err)
	}
	if uuid != "" {
		if err := os.MkdirAll(filepath.Join(dir, "dm"), 0o755); err != nil {
			s.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "dm", "uuid"), []byte(uuid+"\n"), 0o644); err != nil {
			s.t.Fatal(err)
		}
	}
	for _, sl := range slaves {
		if err := os.Symlink(filepath.Join(s.root, "devices", sl), filepath.Join(dir, "slaves", sl)); err != nil {
			s.t.Fatal(err)
		}
	}
	if err := os.Symlink(dir, filepath.Join(s.root, "dev", "block", majMin)); err != nil {
		s.t.Fatal(err)
	}
	return dir
}

// part заводит раздел name диска disk.
func (s *sysfs) part(disk, name, majMin string) {
	s.t.Helper()
	dir := filepath.Join(s.root, "devices", disk, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "partition"), []byte("1\n"), 0o644); err != nil {
		s.t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(s.root, "dev", "block", majMin)); err != nil {
		s.t.Fatal(err)
	}
}

func (s *sysfs) swaps(lines ...string) string {
	s.t.Helper()
	p := filepath.Join(s.root, "swaps")
	body := "Filename\tType\tSize\tUsed\tPriority\n"
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		s.t.Fatal(err)
	}
	return p
}

// stat отдаёт номера устройств по заранее известным путям.
func stat(devs map[string]string) statDev {
	return func(path string, _ bool) (uint32, uint32, error) {
		mm, ok := devs[path]
		if !ok {
			return 0, 0, os.ErrNotExist
		}
		var maj, min uint32
		_, err := fmt.Sscanf(mm, "%d:%d", &maj, &min)
		return maj, min, err
	}
}

func TestCheckLinuxSwap(t *testing.T) {
	s := newSysfs(t)
	s.dev("sda", "8:0", "")
	s.part("sda", "sda2", "8:2")
	s.dev("dm-0", "253:0", "CRYPT-LUKS2-abc-luks", "sda")
	s.dev("dm-1", "253:1", "LVM-xyz", "dm-0")
	s.dev("dm-2", "253:2", "LVM-plain", "sda")
	s.dev("nvme0n1", "259:0", "")
	s.part("nvme0n1", "nvme0n1p1", "259:1")
	devs := stat(map[string]string{
		"/dev/mapper/cryptswap": "253:0",
		"/dev/vg/swap":          "253:1",
		"/dev/vg/plain":         "253:2",
		"/dev/sda2":             "8:2",
		"/swap file":            "259:1",
	})

	for name, tc := range map[string]struct {
		lines []string
		ok    bool
	}{
		"no swap":             {nil, true},
		"luks partition":      {[]string{"/dev/mapper/cryptswap\tpartition\t1\t0\t-2"}, true},
		"lvm on luks":         {[]string{"/dev/vg/swap\tpartition\t1\t0\t-2"}, true},
		"zram":                {[]string{"/dev/zram0\tpartition\t1\t0\t100"}, true},
		"plain partition":     {[]string{"/dev/sda2\tpartition\t1\t0\t-2"}, false},
		"lvm on plain disk":   {[]string{"/dev/vg/plain\tpartition\t1\t0\t-2"}, false},
		"file on plain disk":  {[]string{`/swap\040file` + "\tfile\t1\t0\t-2"}, false},
		"unknown device":      {[]string{"/dev/mystery\tpartition\t1\t0\t-2"}, false},
		"one of two is plain": {[]string{"/dev/mapper/cryptswap\tpartition\t1\t0\t-2", "/dev/sda2\tpartition\t1\t0\t-3"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkLinuxSwap(s.swaps(tc.lines...), s.root, devs)
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok = %v", err, tc.ok)
			}
		})
	}

	err := checkLinuxSwap(s.swaps("/dev/sda2\tpartition\t1\t0\t-2"), s.root, devs)
	if !errors.Is(err, ErrSwapNotEncrypted) {
		t.Errorf("plain swap: err = %v, want ErrSwapNotEncrypted", err)
	}
}

func TestUnescapeProc(t *testing.T) {
	if got := unescapeProc(`/swap\040file`); got != "/swap file" {
		t.Errorf("unescapeProc = %q", got)
	}
	if got := unescapeProc("/swapfile"); got != "/swapfile" {
		t.Errorf("unescapeProc = %q", got)
	}
}
