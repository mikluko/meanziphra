//go:build !darwin

package memguard

import (
	"fmt"
	"runtime"
)

func checkSwap() error {
	return fmt.Errorf("swap encryption cannot be verified on %s", runtime.GOOS)
}
