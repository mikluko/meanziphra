// Package execerr дополняет ошибки внешних команд их stderr.
package execerr

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Wrap добавляет stderr упавшей команды к её ошибке; прочие ошибки возвращает как есть.
func Wrap(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}
