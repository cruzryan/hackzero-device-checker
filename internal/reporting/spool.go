package reporting

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Spool is a small, bounded disk queue for reports collected while a laptop is
// offline. It never retries by inventing a successful result. Its caller owns
// transport, retry timing, and removal after an authenticated 2xx response.
type Spool struct {
	Directory string
	MaxItems  int
}

// Queue writes an envelope atomically. The report signature is checked before
// it can occupy the queue, preventing a local programming error from later
// transmitting an unsigned record.
func (s Spool) Queue(envelope Envelope) (string, error) {
	if !envelope.Verify() {
		return "", errors.New("refusing invalid signed report")
	}
	if s.MaxItems <= 0 {
		return "", errors.New("spool max items must be positive")
	}
	if err := os.MkdirAll(s.Directory, 0700); err != nil {
		return "", fmt.Errorf("create spool: %w", err)
	}
	digest, err := envelope.Digest()
	if err != nil {
		return "", err
	}
	path := filepath.Join(s.Directory, digest+".json")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(s.Directory, ".report-*")
	if err != nil {
		return "", err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	if err := s.trim(); err != nil {
		return "", err
	}
	return path, nil
}

// Pending returns oldest queued reports first. Corrupt files are rejected,
// rather than silently dropped; a support workflow can preserve evidence.
func (s Spool) Pending() ([]Queued, error) {
	entries, err := os.ReadDir(s.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var queued []Queued
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.Directory, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var envelope Envelope
		if err := json.Unmarshal(data, &envelope); err != nil || !envelope.Verify() {
			return nil, fmt.Errorf("invalid queued report %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		queued = append(queued, Queued{Path: path, Envelope: envelope, queuedAt: info.ModTime()})
	}
	// Files created during a single tick can share a filesystem timestamp. The
	// signed collection time is the stable primary ordering; on the intentional
	// full-report + heartbeat tie, retain the useful posture report first.
	sort.Slice(queued, func(i, j int) bool {
		left, right := queued[i].Envelope, queued[j].Envelope
		if !left.CreatedAt.Equal(right.CreatedAt) {
			return left.CreatedAt.Before(right.CreatedAt)
		}
		if left.Kind != right.Kind {
			return left.Kind == "full"
		}
		return queued[i].queuedAt.Before(queued[j].queuedAt)
	})
	return queued, nil
}

// Queued is a verified report awaiting delivery.
type Queued struct {
	Path     string
	Envelope Envelope
	queuedAt time.Time
}

// Remove deletes a report only after the caller has an authenticated success.
func (s Spool) Remove(path string) error {
	relative, err := filepath.Rel(s.Directory, path)
	if err != nil || strings.HasPrefix(relative, "..") || filepath.IsAbs(relative) || !strings.HasSuffix(relative, ".json") {
		return errors.New("refusing path outside spool")
	}
	return os.Remove(path)
}

func (s Spool) trim() error {
	pending, err := s.Pending()
	if err != nil {
		return err
	}
	for len(pending) > s.MaxItems {
		// Bounded storage favors the newest evidence. Deletion is deliberately
		// local only; the service has no ability to delete historic evidence.
		if err := os.Remove(pending[0].Path); err != nil {
			return err
		}
		pending = pending[1:]
	}
	return nil
}
