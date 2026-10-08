//go:build unix

package memguard

import "golang.org/x/sys/unix"

func noCoreDumps() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
