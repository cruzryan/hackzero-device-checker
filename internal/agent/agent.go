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

// Sender sends only a signed envelope to its already-paired report endpoint.
type Sender interface {
	Send(context.Context, reporting.Envelope) error
}

type Collector func() (posture.Observation, error)

// State records completed local collection attempts, not server results.
type State struct {
	LastFullReport time.Time `json:"last_full_report"`
	LastHeartbeat  time.Time `json:"last_heartbeat"`
}

// Runner is dependency-injected to make scheduling and offline behavior testable.
type Runner struct {
	Device    identity.Device
	Collector Collector
	Sender    Sender
	Spool     reporting.Spool
	StatePath string
	Platform  string
	OSVersion string
	Version   string
	Now       func() time.Time
}

// Tick first retries queued envelopes, then collects only work that is due.
// A transport failure queues the signed evidence; it does not change posture.
func (r Runner) Tick(ctx context.Context, checkNow bool) (schedule.Due, error) {
	if r.Sender == nil || r.Collector == nil || r.StatePath == "" {
		return schedule.Due{}, errors.New("incomplete agent configuration")
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Platform == "" {
		r.Platform = runtime.GOOS
	}
	if r.OSVersion == "" {
		r.OSVersion = runtime.GOOS
	}
	if err := r.flush(ctx); err != nil {
		return schedule.Due{}, err
	}
	state, err := loadState(r.StatePath)
	if err != nil {
		return schedule.Due{}, err
	}
	now := r.Now().UTC()
	due := schedule.Evaluate(now, state.LastFullReport, state.LastHeartbeat, checkNow)
	if due.FullReport {
		observation, collectionErr := r.Collector()
		if collectionErr != nil {
			observation = posture.Observation{}
		}
		report := posture.Evaluate(observation, r.Platform, r.OSVersion, r.Version, now)
		envelope, envelopeErr := reporting.NewEnvelope(r.Device, report, now)
		if envelopeErr != nil {
			return due, envelopeErr
		}
		if err := r.deliver(ctx, envelope); err != nil {
			return due, err
		}
		state.LastFullReport = now
	}
	if due.Heartbeat {
		heartbeat, envelopeErr := reporting.NewHeartbeat(r.Device, now)
		if envelopeErr != nil {
			return due, envelopeErr
		}
		if err := r.deliver(ctx, heartbeat); err != nil {
			return due, err
		}
		state.LastHeartbeat = now
	}
	return due, saveState(r.StatePath, state)
}

func (r Runner) deliver(ctx context.Context, envelope reporting.Envelope) error {
	if err := r.Sender.Send(ctx, envelope); err == nil {
		return nil
	}
	spool := r.Spool
	if spool.MaxItems == 0 {
		spool.MaxItems = queueLimit
	}
	if _, err := spool.Queue(envelope); err != nil {
		return fmt.Errorf("queue offline report: %w", err)
	}
	return nil
}

func (r Runner) flush(ctx context.Context) error {
	if r.Spool.MaxItems == 0 {
		r.Spool.MaxItems = queueLimit
	}
	pending, err := r.Spool.Pending()
	if err != nil {
		return err
	}
	for _, queued := range pending {
		if err := r.Sender.Send(ctx, queued.Envelope); err != nil {
			return nil
		}
		if err := r.Spool.Remove(queued.Path); err != nil {
			return err
		}
	}
	return nil
}

func loadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("read agent state: %w", err)
	}
	return state, nil
}

func saveState(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".agent-state-*")
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
