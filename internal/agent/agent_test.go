package agent

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/posture"
	"github.com/hackzero/device-checker/internal/reporting"
)

type sender struct {
	sent []reporting.Envelope
	fail bool
}

func (s *sender) Send(_ context.Context, envelope reporting.Envelope) error {
	if s.fail {
		return errors.New("offline")
	}
	s.sent = append(s.sent, envelope)
	return nil
}

func TestTickQueuesOfflineAndRetriesInOrder(t *testing.T) {
	d, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	s := &sender{fail: true}
	r := Runner{Device: d, Collector: func() (posture.Observation, error) { return posture.Observation{}, nil }, Sender: s, Spool: reporting.Spool{Directory: filepath.Join(t.TempDir(), "queue"), MaxItems: 3}, StatePath: filepath.Join(t.TempDir(), "state.json"), Now: func() time.Time { return now }}
	due, err := r.Tick(context.Background(), false)
	if err != nil || !due.FullReport || !due.Heartbeat {
		t.Fatalf("due=%#v err=%v", due, err)
	}
	pending, err := r.Spool.Pending()
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending=%d err=%v", len(pending), err)
	}
	s.fail = false
	now = now.Add(time.Hour)
	if _, err := r.Tick(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	pending, err = r.Spool.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending=%d err=%v", len(pending), err)
	}
	if len(s.sent) != 2 || s.sent[0].Kind != "full" || s.sent[1].Kind != "heartbeat" {
		t.Fatalf("sent=%#v", s.sent)
	}
}

func TestHeartbeatNeverReplacesDueFullReport(t *testing.T) {
	d, _ := identity.New()
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	s := &sender{}
	r := Runner{Device: d, Collector: func() (posture.Observation, error) { return posture.Observation{}, nil }, Sender: s, Spool: reporting.Spool{Directory: filepath.Join(t.TempDir(), "queue"), MaxItems: 3}, StatePath: filepath.Join(t.TempDir(), "state.json"), Now: func() time.Time { return now }}
	if _, err := r.Tick(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	now = now.Add(7 * time.Hour)
	if _, err := r.Tick(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(s.sent) != 3 || s.sent[2].Kind != "heartbeat" {
		t.Fatalf("sent=%d final=%s", len(s.sent), s.sent[len(s.sent)-1].Kind)
	}
}
