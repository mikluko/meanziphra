package execerr

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestWrap(t *testing.T) {
	_, err := exec.Command("sh", "-c", "echo boom >&2; exit 3").Output()
	got := Wrap(err)
	if !strings.Contains(got.Error(), "boom") {
		t.Errorf("Wrap = %v, want stderr in it", got)
	}
	var ee *exec.ExitError
	if !errors.As(got, &ee) {
		t.Error("Wrap lost the *exec.ExitError")
	}
	plain := errors.New("plain")
	if Wrap(plain) != plain {
		t.Error("Wrap changed an error without stderr")
	}
}
