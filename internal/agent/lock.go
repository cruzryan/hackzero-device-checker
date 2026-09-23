package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LockStaleAfter is how old a lock file must be before a new run may take it
// over (a crashed run never releases its lock).
const LockStaleAfter = 2 * time.Minute

// ErrBusy means another collector run holds the lock.
var ErrBusy = errors.New("another Device Checker run is in progress")

// AcquireLock makes only one collector run at a time. It creates path with
// O_EXCL, waiting up to wait for a running holder, and replaces a lock older
// than LockStaleAfter. The returned release removes the lock.
func AcquireLock(path string, wait time.Duration) (release func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = fmt.Fprintf(file, "%d %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
			_ = file.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > LockStaleAfter {
			_ = os.Remove(path)
			continue
		}
		if !time.Now().Before(deadline) {
			return nil, ErrBusy
		}
		time.Sleep(200 * time.Millisecond)
	}
}
