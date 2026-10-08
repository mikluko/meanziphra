package memguard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// statDev возвращает устройство, на котором лежит path: для раздела подкачки — само устройство (st_rdev),
// для файла подкачки — устройство его файловой системы (st_dev).
type statDev func(path string, file bool) (major, minor uint32, err error)

// checkLinuxSwap проверяет, что каждая активная подкачка из procSwaps лежит в памяти (zram) или на dm-crypt,
// по дереву sysfs. Подкачки нет совсем — тоже успех. Устройство, про которое ничего нельзя выяснить, — отказ.
func checkLinuxSwap(procSwaps, sysfs string, stat statDev) error {
	b, err := os.ReadFile(procSwaps)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Scan() // заголовок: Filename Type Size Used Priority
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		path := unescapeProc(f[0])
		if strings.HasPrefix(filepath.Base(path), "zram") {
			continue
		}
		major, minor, err := stat(path, f[1] == "file")
		if err != nil {
			return fmt.Errorf("swap %s: %w", path, err)
		}
		ok, err := onDMCrypt(sysfs, filepath.Join(sysfs, "dev", "block", fmt.Sprintf("%d:%d", major, minor)), 0)
		if err != nil {
			return fmt.Errorf("swap %s: %w", path, err)
		}
		if !ok {
			return fmt.Errorf("swap %s: %w", path, ErrSwapNotEncrypted)
		}
	}
	return sc.Err()
}

// onDMCrypt сообщает, лежит ли блочное устройство из sysfs dev целиком на dm-crypt: оно само — цель crypt
// (dm/uuid начинается с CRYPT-) или у него есть нижележащие устройства (slaves) и все они лежат на dm-crypt.
// Раздел проверяется по своему диску.
func onDMCrypt(sysfs, dev string, depth int) (bool, error) {
	if depth > 16 {
		return false, errors.New("device stack too deep")
	}
	real, err := filepath.EvalSymlinks(dev)
	if err != nil {
		return false, fmt.Errorf("block device not in sysfs: %w", err)
	}
	if _, err := os.Stat(filepath.Join(real, "partition")); err == nil {
		return onDMCrypt(sysfs, filepath.Dir(real), depth+1)
	}
	if uuid, err := os.ReadFile(filepath.Join(real, "dm", "uuid")); err == nil && bytes.HasPrefix(uuid, []byte("CRYPT-")) {
		return true, nil
	}
	slaves, err := os.ReadDir(filepath.Join(real, "slaves"))
	if err != nil || len(slaves) == 0 {
		return false, nil
	}
	for _, s := range slaves {
		ok, err := onDMCrypt(sysfs, filepath.Join(real, "slaves", s.Name()), depth+1)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// unescapeProc раскрывает восьмеричные экранирования вроде \040, которыми ядро пишет пробелы в /proc/swaps.
func unescapeProc(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
