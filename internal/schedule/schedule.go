// Package schedule makes collection due times explicit and testable. A missed
// schedule is not a posture failure; that decision belongs to server freshness.
package schedule

import "time"

const (
	FullReportEvery = 24 * time.Hour
	HeartbeatEvery  = 6 * time.Hour
)

// Due describes local work which may be attempted now. CheckNow has priority
// and is cleared by the caller only after a collection attempt.
type Due struct{ FullReport, Heartbeat bool }

func Evaluate(now, lastFull, lastHeartbeat time.Time, checkNow bool) Due {
	return Due{
		FullReport: checkNow || lastFull.IsZero() || !now.Before(lastFull.Add(FullReportEvery)),
		Heartbeat:  lastHeartbeat.IsZero() || !now.Before(lastHeartbeat.Add(HeartbeatEvery)),
	}
}
