//go:build !unix

package memguard

func noCoreDumps() error {
	return nil
}
