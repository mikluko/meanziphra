package memguard

import "golang.org/x/sys/unix"

func checkSwap() error {
	return checkLinuxSwap("/proc/swaps", "/sys", func(path string, file bool) (uint32, uint32, error) {
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			return 0, 0, err
		}
		dev := st.Rdev
		if file {
			dev = st.Dev
		}
		return unix.Major(dev), unix.Minor(dev), nil
	})
}
