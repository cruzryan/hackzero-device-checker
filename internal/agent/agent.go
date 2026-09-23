// Package agent owns durable local scheduling and delivery. It never decides
// whether missing evidence is a failed device setting: that is service-side
// freshness logic based on receipt timestamps.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/posture"
	"github.com/hackzero/device-checker/internal/reporting"
	"github.com/hackzero/device-checker/internal/schedule"
)

const queueLimit = 96

// Sources of a run, recorded in RunResult.
const (
	SourceManual     = "manual"
	SourceBackground = "background"
)

// Delivery outcomes, recorded in RunResult.
const (
	DeliveryUploaded = "uploaded"
	DeliveryQueued   = "queued"
	DeliveryRejected = "rejected"
	DeliveryNotSent  = "not_sent"
)

// ServerDevice is the "device" object the service returns for a full report:
// its verdict on this device as plain sentences.
type ServerDevice struct {
	Status   string   `json:"status"`
	Problems []string `json:"problems"`
	Warnings []string `json:"warnings"`
}

// SendResult is what a Sender learned from the service. HTTPStatus is 0 when
// no response was received (a network error).
type SendResult struct {
	HTTPStatus int
	Device     *ServerDevice
	// ErrorCode is the service's short machine code on a rejection, if any.
	ErrorCode string
}

// Sender sends only a signed envelope to its already-paired report endpoint.
// It returns a non-nil error for anything but a 2xx response.
type Sender interface {
	Send(context.Context, reporting.Envelope) (SendResult, error)
}

type Collector func() (posture.Observation, error)

// State records completed local collection attempts, not server results.
type State struct {
	LastFullReport time.Time `json:"last_full_report"`
	LastHeartbeat  time.Time `json:"last_heartbeat"`
}

// RunResult is one full report and what happened to it. It is printed by
// `report` and persisted as last-report.json by every run that sends a full
// report.
type RunResult struct {
	Source     string         `json:"source"`
	CheckedAt  time.Time      `json:"checked_at"`
	Report     posture.Report `json:"report"`
	Delivery   string         `json:"delivery"`
	HTTPStatus int            `json:"http_status,omitempty"`
	Error      string         `json:"error,omitempty"`
	Server     *ServerDevice  `json:"server,omitempty"`
}

// Outcome describes one Run.
type Outcome struct {
	Due schedule.Due
	// Full is set when a full report was collected and sent (or queued).
	Full *RunResult
	// HeartbeatDelivery is set when a heartbeat was sent.
	HeartbeatDelivery string
}

// Runner is dependency-injected to make scheduling and offline behavior testable.
type Runner struct {
	Device    identity.Device
	Collector Collector
	Sender    Sender
	Spool     reporting.Spool
	StatePath string
	// LastReportPath, when set, receives every full report's RunResult.
	LastReportPath string
	// Source is SourceManual or SourceBackground (the default).
	Source   string
	Platform string
	// OSVersion overrides the version the collector read; normally empty.
	OSVersion string
	Version   string
	Now       func() time.Time
}

// Tick first retries queued envelopes, then collects only work that is due.
// A transport failure queues the signed evidence; it does not change posture.
func (r Runner) Tick(ctx context.Context, checkNow bool) (schedule.Due, error) {
	outcome, err := r.Run(ctx, checkNow)
	return outcome.Due, err
}

// Run is Tick with the full delivery outcome.
func (r Runner) Run(ctx context.Context, checkNow bool) (Outcome, error) {
	if r.Sender == nil || r.Collector == nil || r.StatePath == "" {
		return Outcome{}, errors.New("incomplete agent configuration")
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Platform == "" {
		r.Platform = runtime.GOOS
	}
	if r.Source == "" {
		r.Source = SourceBackground
	}
	if r.Spool.MaxItems == 0 {
		r.Spool.MaxItems = queueLimit
	}
	if err := r.flush(ctx); err != nil {
		return Outcome{}, err
	}
	state := LoadState(r.StatePath)
	now := r.Now().UTC()
	outcome := Outcome{Due: schedule.Evaluate(now, state.LastFullReport, state.LastHeartbeat, checkNow)}
	if outcome.Due.FullReport {
		observation, collectionErr := r.Collector()
		if collectionErr != nil {
			// A collection error is not evidence of failure: every signal
			// becomes unknown.
			observation = posture.Observation{}
		}
		report := posture.Evaluate(observation, r.Platform, r.OSVersion, r.Version, now)
		envelope, err := reporting.NewEnvelope(r.Device, report, now)
		if err != nil {
			return outcome, err
		}
		result := &RunResult{Source: r.Source, CheckedAt: now, Report: report, Delivery: DeliveryNotSent}
		if err := r.deliver(ctx, envelope, result); err != nil {
			return outcome, err
		}
		outcome.Full = result
		state.LastFullReport = now
		if r.LastReportPath != "" {
			if err := SaveLastReport(r.LastReportPath, *result); err != nil {
				return outcome, err
			}
		}
	}
	if outcome.Due.Heartbeat {
		heartbeat, err := reporting.NewHeartbeat(r.Device, now)
		if err != nil {
			return outcome, err
		}
		result := &RunResult{}
		if err := r.deliver(ctx, heartbeat, result); err != nil {
			return outcome, err
		}
		outcome.HeartbeatDelivery = result.Delivery
		state.LastHeartbeat = now
	}
	return outcome, saveState(r.StatePath, state)
}

// Classify applies the delivery rules: 2xx uploaded; no response, 5xx or 429
// queued for retry; any other 4xx rejected and never retried.
func Classify(result SendResult, err error) (delivery string, message string) {
	status := result.HTTPStatus
	switch {
	case err == nil:
		return DeliveryUploaded, ""
	case status == 0:
		return DeliveryQueued, "Could not reach HackZero. The report is saved on this computer and will be sent automatically."
	case status >= 500 || status == 429:
		return DeliveryQueued, fmt.Sprintf("HackZero is temporarily unavailable (HTTP %d). The report is saved on this computer and will be sent automatically.", status)
	case status == 401 || status == 404 || status == 410:
		return DeliveryRejected, fmt.Sprintf("This computer is no longer connected to HackZero (HTTP %d). Connect it again to keep reporting.", status)
	case status >= 400 && status < 500:
		detail := ""
		if code := posture.SanitizeToken(result.ErrorCode); code != "" {
			detail = ": " + code
		}
		return DeliveryRejected, fmt.Sprintf("HackZero rejected the report (HTTP %d%s).", status, detail)
	default:
		return DeliveryQueued, fmt.Sprintf("Unexpected response from HackZero (HTTP %d). The report is saved and will be sent again.", status)
	}
}

// shortASCII keeps printable ASCII only and caps the length at 300.
func shortASCII(message string) string {
	out := make([]byte, 0, len(message))
	for i := 0; i < len(message) && len(out) < 300; i++ {
		if c := message[i]; c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	return string(out)
}

func (r Runner) deliver(ctx context.Context, envelope reporting.Envelope, result *RunResult) error {
	sent, sendErr := r.Sender.Send(ctx, envelope)
	delivery, message := Classify(sent, sendErr)
	result.Delivery = delivery
	result.HTTPStatus = sent.HTTPStatus
	result.Error = shortASCII(message)
	if delivery == DeliveryUploaded {
		result.Server = sent.Device
	}
	if delivery != DeliveryQueued {
		return nil
	}
	if _, err := r.Spool.Queue(envelope); err != nil {
		return fmt.Errorf("queue offline report: %w", err)
	}
	return nil
}

func (r Runner) flush(ctx context.Context) error {
	pending, err := r.Spool.Pending()
	if err != nil {
		return err
	}
	for _, queued := range pending {
		sent, sendErr := r.Sender.Send(ctx, queued.Envelope)
		delivery, message := Classify(sent, sendErr)
		if delivery == DeliveryQueued {
			// Keep order: stop at the first report the service cannot take yet.
			return nil
		}
		// Uploaded, or rejected (never retried): either way it leaves the queue.
		if err := r.Spool.Remove(queued.Path); err != nil {
			return err
		}
		if queued.Envelope.Kind == "full" && r.LastReportPath != "" {
			r.updateLastReport(queued.Envelope, delivery, sent, message)
		}
	}
	return nil
}

// updateLastReport records the late delivery of the queued report that
// last-report.json describes, so a "queued" result does not linger after it
// was sent. It is best effort.
func (r Runner) updateLastReport(envelope reporting.Envelope, delivery string, sent SendResult, message string) {
	last, err := LoadLastReport(r.LastReportPath)
	if err != nil || last.Delivery != DeliveryQueued || !last.Report.CollectedAt.Equal(envelope.Report.CollectedAt) {
		return
	}
	last.Delivery = delivery
	last.HTTPStatus = sent.HTTPStatus
	last.Error = shortASCII(message)
	if delivery == DeliveryUploaded {
		last.Server = sent.Device
	}
	_ = SaveLastReport(r.LastReportPath, last)
}

// SaveLastReport writes last-report.json atomically with owner-only access.
func SaveLastReport(path string, result RunResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// LoadLastReport reads last-report.json.
func LoadLastReport(path string) (RunResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RunResult{}, err
	}
	var result RunResult
	if err := json.Unmarshal(data, &result); err != nil {
		return RunResult{}, fmt.Errorf("read last report: %w", err)
	}
	return result, nil
}

// LoadState reads the scheduler state. A missing or corrupt file is treated
// as "never ran", which only makes a report due sooner.
func LoadState(path string) State {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}
	}
	var state State
	if json.Unmarshal(data, &state) != nil {
		return State{}
	}
	return state
}

func saveState(path string, state State) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
