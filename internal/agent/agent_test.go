package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/posture"
	"github.com/hackzero/device-checker/internal/reporting"
)

// sender replies with a scripted HTTP status (0 = network error).
type sender struct {
	sent   []reporting.Envelope
	fail   bool
	status int
	device *ServerDevice
}

func (s *sender) Send(_ context.Context, envelope reporting.Envelope) (SendResult, error) {
	if s.fail {
		return SendResult{}, errors.New("offline")
	}
	if s.status >= 300 {
		return SendResult{HTTPStatus: s.status, ErrorCode: "invalid_report"}, errors.New("server error")
	}
	s.sent = append(s.sent, envelope)
	return SendResult{HTTPStatus: 200, Device: s.device}, nil
}

func newRunner(t *testing.T, s Sender, now *time.Time) Runner {
	t.Helper()
	d, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return Runner{
		Device:         d,
		Collector:      func() (posture.Observation, error) { return posture.Observation{OSVersion: "26.5.2"}, nil },
		Sender:         s,
		Spool:          reporting.Spool{Directory: filepath.Join(dir, "queue"), MaxItems: 3},
		StatePath:      filepath.Join(dir, "state.json"),
		LastReportPath: filepath.Join(dir, "last-report.json"),
		Now:            func() time.Time { return *now },
	}
}

func TestTickQueuesOfflineAndRetriesInOrder(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	s := &sender{fail: true}
	r := newRunner(t, s, &now)
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
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	s := &sender{}
	r := newRunner(t, s, &now)
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

func TestDeliveryRules(t *testing.T) {
	cases := []struct {
		name     string
		sender   *sender
		delivery string
		queued   int
		status   int
	}{
		{"2xx uploaded", &sender{device: &ServerDevice{Status: "fail", Problems: []string{"Screen lock takes 35 minutes on AC power."}}}, DeliveryUploaded, 0, 200},
		{"network error queued", &sender{fail: true}, DeliveryQueued, 2, 0},
		{"5xx queued", &sender{status: 503}, DeliveryQueued, 2, 503},
		{"429 queued", &sender{status: 429}, DeliveryQueued, 2, 429},
		{"401 rejected, not queued", &sender{status: 401}, DeliveryRejected, 0, 401},
		{"404 rejected, not queued", &sender{status: 404}, DeliveryRejected, 0, 404},
		{"400 rejected, not queued", &sender{status: 400}, DeliveryRejected, 0, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
			r := newRunner(t, c.sender, &now)
			r.Source = SourceManual
			outcome, err := r.Run(context.Background(), true)
			if err != nil {
				t.Fatal(err)
			}
			full := outcome.Full
			if full == nil || full.Delivery != c.delivery || full.HTTPStatus != c.status || full.Source != SourceManual {
				t.Fatalf("full=%#v", full)
			}
			if got := r.Spool.Count(); got != c.queued {
				t.Fatalf("queued %d want %d", got, c.queued)
			}
			if (c.delivery == DeliveryUploaded) != (full.Error == "") {
				t.Fatalf("error message %q", full.Error)
			}
			if c.delivery == DeliveryUploaded && (full.Server == nil || full.Server.Status != "fail") {
				t.Fatalf("server verdict not captured: %#v", full.Server)
			}
			if c.status == 401 && !strings.Contains(full.Error, "no longer connected") {
				t.Fatalf("401 must explain the disconnection: %q", full.Error)
			}
			if full.Report.OSVersion != "26.5.2" {
				t.Fatalf("os_version %q", full.Report.OSVersion)
			}
			last, err := LoadLastReport(r.LastReportPath)
			if err != nil || last.Delivery != c.delivery || !last.CheckedAt.Equal(now) {
				t.Fatalf("last=%#v err=%v", last, err)
			}
			if runtime.GOOS != "windows" {
				info, _ := os.Stat(r.LastReportPath)
				if info.Mode().Perm() != 0600 {
					t.Fatalf("last-report mode %v", info.Mode().Perm())
				}
			}
		})
	}
}

func TestLastReportIsTheExactSignedReport(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	s := &sender{}
	r := newRunner(t, s, &now)
	if _, err := r.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	last, err := LoadLastReport(r.LastReportPath)
	if err != nil {
		t.Fatal(err)
	}
	persisted, _ := json.Marshal(last.Report)
	signed, _ := json.Marshal(s.sent[0].Report)
	if string(persisted) != string(signed) {
		t.Fatalf("persisted %s\nsigned %s", persisted, signed)
	}
	if last.Source != SourceBackground {
		t.Fatalf("default source %q", last.Source)
	}
}

func TestQueuedReportLaterUploadedUpdatesLastReport(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	s := &sender{fail: true}
	r := newRunner(t, s, &now)
	if _, err := r.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	s.fail = false
	s.device = &ServerDevice{Status: "pass", Problems: []string{}, Warnings: []string{}}
	now = now.Add(time.Minute)
	outcome, err := r.Run(context.Background(), false)
	if err != nil || outcome.Full != nil {
		t.Fatalf("no new full report is due: %#v %v", outcome, err)
	}
	last, err := LoadLastReport(r.LastReportPath)
	if err != nil || last.Delivery != DeliveryUploaded || last.Server == nil || last.Server.Status != "pass" || last.Error != "" {
		t.Fatalf("last=%#v err=%v", last, err)
	}
}

func TestRejectedQueuedReportIsDroppedNotRetried(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	s := &sender{fail: true}
	r := newRunner(t, s, &now)
	if _, err := r.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	s.fail, s.status = false, 401
	now = now.Add(time.Minute)
	if _, err := r.Run(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if r.Spool.Count() != 0 {
		t.Fatal("rejected reports must leave the queue")
	}
	if last, _ := LoadLastReport(r.LastReportPath); last.Delivery != DeliveryRejected {
		t.Fatalf("last=%#v", last)
	}
}

func TestCorruptQueueFileIsMovedAsideNotFatal(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	s := &sender{}
	r := newRunner(t, s, &now)
	if err := os.MkdirAll(r.Spool.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(r.Spool.Directory, "0000.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background(), true); err != nil {
		t.Fatalf("corrupt queue must not fail the run: %v", err)
	}
	if _, err := os.Stat(bad + reporting.CorruptSuffix); err != nil {
		t.Fatalf("corrupt file not moved aside: %v", err)
	}
	if len(s.sent) != 2 {
		t.Fatalf("sent %d", len(s.sent))
	}
}

func TestCorruptStateIsTreatedAsNeverRan(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	r := newRunner(t, &sender{}, &now)
	if err := os.WriteFile(r.StatePath, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	outcome, err := r.Run(context.Background(), false)
	if err != nil || !outcome.Due.FullReport {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
}

func TestClassifyMessagesAreShortASCII(t *testing.T) {
	for _, status := range []int{0, 301, 400, 401, 403, 404, 410, 429, 500, 503} {
		err := errors.New("x")
		delivery, message := Classify(SendResult{HTTPStatus: status, ErrorCode: "bad <é> code"}, err)
		if delivery == DeliveryUploaded || message == "" || len(message) > 300 {
			t.Errorf("%d: %s %q", status, delivery, message)
		}
		for _, b := range []byte(message) {
			if b >= 0x7f || b < 0x20 {
				t.Errorf("%d: non-ASCII message %q", status, message)
			}
		}
	}
	if d, m := Classify(SendResult{HTTPStatus: 201}, nil); d != DeliveryUploaded || m != "" {
		t.Error("2xx must upload")
	}
}

func TestLockIsExclusiveAndStaleLocksExpire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "device-checker.lock")
	release, err := AcquireLock(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := AcquireLock(path, 300*time.Millisecond); !errors.Is(err, ErrBusy) {
		t.Fatalf("second run must be busy, got %v", err)
	}
	if time.Since(started) < 250*time.Millisecond {
		t.Fatal("second run must wait before giving up")
	}
	release()
	release2, err := AcquireLock(path, 0)
	if err != nil {
		t.Fatalf("released lock must be free: %v", err)
	}
	// A crashed holder leaves a lock behind; after two minutes it is stale.
	old := time.Now().Add(-LockStaleAfter - time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	release3, err := AcquireLock(path, 0)
	if err != nil {
		t.Fatalf("stale lock must be taken over: %v", err)
	}
	release3()
	release2() // releasing twice is harmless
}
