// Package memguard не даёт ключу якоря попасть на диск через подкачку или дамп памяти процесса.
package memguard

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrSwapNotEncrypted — подкачка не шифруется, и память процесса может лечь на диск открытым текстом.
var ErrSwapNotEncrypted = errors.New("swap is not encrypted")

// CheckSwap возвращает ошибку, если подкачка не шифруется или на этой ОС это нельзя проверить.
func CheckSwap() error {
	return checkSwap()
}

// NoCoreDumps запрещает процессу оставлять дамп памяти при падении.
func NoCoreDumps() error {
	return noCoreDumps()
}

// swapEncrypted читает xsu_encrypted из struct xsw_usage (sys/sysctl.h в SDK macOS):
// после трёх u_int64_t и одного u_int32_t идёт boolean_t шириной 4 байта.
func swapEncrypted(b []byte) (bool, error) {
	const off, size = 28, 32
	if len(b) < size {
		return false, fmt.Errorf("vm.swapusage: %d bytes, want %d", len(b), size)
	}
	return binary.NativeEndian.Uint32(b[off:off+4]) != 0, nil
}
