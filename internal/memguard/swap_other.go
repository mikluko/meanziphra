//go:build !darwin && !linux

package memguard

import (
	"errors"
	"runtime"
)

var errSwapUnverifiable = errors.New("swap encryption cannot be verified on " + runtime.GOOS)

func checkSwap() error {
	return errSwapUnverifiable
}
