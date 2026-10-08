package memguard

import (
	"encoding/binary"
	"runtime"
	"testing"
)

func usage(encrypted uint32) []byte {
	b := make([]byte, 32)
	binary.NativeEndian.PutUint64(b[0:], 2048<<20)
	binary.NativeEndian.PutUint32(b[24:], 16384)
	binary.NativeEndian.PutUint32(b[28:], encrypted)
	return b
}

func TestSwapEncrypted(t *testing.T) {
	if ok, err := swapEncrypted(usage(1)); err != nil || !ok {
		t.Errorf("encrypted: %v, %v", ok, err)
	}
	if ok, err := swapEncrypted(usage(0)); err != nil || ok {
		t.Errorf("plain: %v, %v", ok, err)
	}
	if _, err := swapEncrypted(make([]byte, 16)); err == nil {
		t.Error("short buffer accepted")
	}
}

// На macOS подкачка шифруется всегда; в Linux ответ зависит от машины; на прочих ОС CheckSwap обязан отказать.
func TestCheckSwap(t *testing.T) {
	err := CheckSwap()
	switch runtime.GOOS {
	case "darwin":
		if err != nil {
			t.Errorf("CheckSwap on darwin: %v", err)
		}
	case "linux":
		t.Logf("CheckSwap on this linux host: %v", err)
	default:
		if err == nil {
			t.Error("CheckSwap passed where it cannot verify anything")
		}
	}
}

func TestNoCoreDumps(t *testing.T) {
	if err := NoCoreDumps(); err != nil {
		t.Fatal(err)
	}
}
