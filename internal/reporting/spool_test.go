package reporting

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/posture"
)

func TestSpoolQueuesVerifiedReportsAndRejectsEscapes(t *testing.T) {
	d, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvelope(d, posture.Report{SchemaVersion: 1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := Spool{Directory: filepath.Join(t.TempDir(), "queue"), MaxItems: 2}
	path, err := s.Queue(e)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.Pending()
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending=%d err=%v", len(pending), err)
	}
	if err := s.Remove(filepath.Join(s.Directory, "..", "other.json")); err == nil {
		t.Fatal("accepted outside path")
	}
	if err := s.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("report remained after remove")
	}
}

func TestSpoolRejectsTamperedReport(t *testing.T) {
	d, _ := identity.New()
	e, _ := NewEnvelope(d, posture.Report{SchemaVersion: 1}, time.Now())
	e.Signature = "tampered"
	if _, err := (Spool{Directory: t.TempDir(), MaxItems: 1}).Queue(e); err == nil {
		t.Fatal("accepted unsigned report")
	}
}
