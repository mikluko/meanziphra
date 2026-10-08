package memguard

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func checkSwap() error {
	b, err := unix.SysctlRaw("vm.swapusage")
	if err != nil {
		return fmt.Errorf("vm.swapusage: %w", err)
	}
	ok, err := swapEncrypted(b)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSwapNotEncrypted
	}
	return nil
}
