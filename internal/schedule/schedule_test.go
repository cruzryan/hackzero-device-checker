package schedule

import (
	"testing"
	"time"
)

func TestScheduleNeverTreatsOfflineTimeAsFailure(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	due := Evaluate(now, now.Add(-25*time.Hour), now.Add(-7*time.Hour), false)
	if !due.FullReport || !due.Heartbeat {
		t.Fatal("expected work to be due")
	}
	// Due work is a local retry opportunity, not a posture status or a failure.
}

func TestCheckNowRequestsFullReport(t *testing.T) {
	now := time.Now()
	if !Evaluate(now, now, now, true).FullReport {
		t.Fatal("check-now was ignored")
	}
}
