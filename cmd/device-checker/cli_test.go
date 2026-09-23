package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hackzero/device-checker/internal/agent"
	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/posture"
	"github.com/hackzero/device-checker/internal/reporting"
	"github.com/hackzero/device-checker/internal/schedule"
)

func pairedDir(t *testing.T) (string, identity.Device) {
	t.Helper()
	dir := t.TempDir()
	device, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := device.Save(identityPath(dir)); err != nil {
		t.Fatal(err)
	}
	pairing, _ := json.Marshal(savedState{Identity: device, ReportURL: "https://example.test/api/trust/device-checker/reports", WorkspaceName: "Acme", PersonName: "Alex"})
	if err := os.WriteFile(pairingPath(dir), pairing, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, device
}

func TestLastOutput(t *testing.T) {
	dir := t.TempDir()
	if got := string(lastOutput(dir)); got != `{"available":false}` {
		t.Fatalf("missing: %s", got)
	}
	if err := os.WriteFile(lastReportPath(dir), []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := string(lastOutput(dir)); got != `{"available":false}` {
		t.Fatalf("corrupt: %s", got)
	}
	result := agent.RunResult{Source: agent.SourceManual, CheckedAt: time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC), Report: posture.Report{SchemaVersion: 1}, Delivery: agent.DeliveryQueued, Error: "offline"}
	if err := agent.SaveLastReport(lastReportPath(dir), result); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(lastOutput(dir), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"source", "checked_at", "report", "delivery", "error"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("last-report missing %q: %v", key, decoded)
		}
	}
}

func TestDiagnoseShapeAndNoPrivateKey(t *testing.T) {
	dir, device := pairedDir(t)
	if err := os.WriteFile(agentStatePath(dir), []byte(`{"last_full_report":"2026-09-23T18:46:51Z","last_heartbeat":"2026-09-23T18:26:44Z"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := agent.SaveLastReport(lastReportPath(dir), agent.RunResult{Source: agent.SourceBackground, Delivery: agent.DeliveryUploaded}); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(buildDiagnosis(dir, "26.5.2 <x>"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for key := range decoded {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := "agent_state,checker_version,device_id,last,os_version,paired,person_name,platform,queue_count,workspace_name"
	if strings.Join(keys, ",") != want {
		t.Fatalf("keys %v", keys)
	}
	if decoded["paired"] != true || decoded["device_id"] != device.ID || decoded["os_version"] != "26.5.2x" || decoded["queue_count"] != float64(0) {
		t.Fatalf("diagnosis %s", data)
	}
	if last, ok := decoded["last"].(map[string]any); !ok || last["delivery"] != "uploaded" {
		t.Fatalf("last %v", decoded["last"])
	}
	identityFile, _ := os.ReadFile(identityPath(dir))
	var stored struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(identityFile, &stored); err != nil || stored.PrivateKey == "" {
		t.Fatal("test setup: identity has no private key")
	}
	if strings.Contains(string(data), stored.PrivateKey) || strings.Contains(string(data), "private") {
		t.Fatal("diagnose must never include private key material")
	}
}

func TestDiagnoseUnpaired(t *testing.T) {
	data, _ := json.Marshal(buildDiagnosis(t.TempDir(), ""))
	want := `"paired":false`
	if !strings.Contains(string(data), want) || !strings.Contains(string(data), `"agent_state":null`) || !strings.Contains(string(data), `"last":null`) {
		t.Fatalf("unpaired diagnosis %s", data)
	}
}

func TestReportSenderCapturesServerVerdict(t *testing.T) {
	var status int
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	device, _ := identity.New()
	envelope, _ := reporting.NewEnvelope(device, posture.Report{SchemaVersion: 1}, time.Now())
	sender := reportSender{url: server.URL}

	status, body = 200, `{"ok":true,"received_at":"2026-09-23T18:00:00Z","device":{"status":"fail","problems":["Screen lock takes 35 minutes on AC power."],"warnings":[]}}`
	result, err := sender.Send(context.Background(), envelope)
	if err != nil || result.HTTPStatus != 200 || result.Device == nil || result.Device.Status != "fail" || len(result.Device.Problems) != 1 {
		t.Fatalf("2xx: %#v %v", result, err)
	}
	if d, _ := agent.Classify(result, err); d != agent.DeliveryUploaded {
		t.Fatal(d)
	}

	status, body = 200, `{"ok":true,"received_at":"x"}`
	result, err = sender.Send(context.Background(), envelope)
	if err != nil || result.Device != nil {
		t.Fatalf("heartbeat-style response: %#v %v", result, err)
	}

	status, body = 401, `{"error":"unknown_device"}`
	result, err = sender.Send(context.Background(), envelope)
	if d, msg := agent.Classify(result, err); d != agent.DeliveryRejected || result.ErrorCode != "unknown_device" || !strings.Contains(msg, "no longer connected") {
		t.Fatalf("401: %#v %s", result, msg)
	}

	status, body = 503, `<html>down</html>`
	result, err = sender.Send(context.Background(), envelope)
	if d, _ := agent.Classify(result, err); d != agent.DeliveryQueued {
		t.Fatalf("503: %#v", result)
	}

	server.Close()
	result, err = sender.Send(context.Background(), envelope)
	if d, _ := agent.Classify(result, err); d != agent.DeliveryQueued || result.HTTPStatus != 0 {
		t.Fatalf("network: %#v %v", result, err)
	}
}

func TestTickSummary(t *testing.T) {
	full := &agent.RunResult{Delivery: agent.DeliveryRejected}
	if got := tickSummary(agent.Outcome{Due: schedule.Due{FullReport: true}, Full: full}, 0)["delivery"]; got != agent.DeliveryRejected {
		t.Fatal(got)
	}
	if got := tickSummary(agent.Outcome{HeartbeatDelivery: agent.DeliveryQueued}, 1)["delivery"]; got != agent.DeliveryQueued {
		t.Fatal(got)
	}
	if got := tickSummary(agent.Outcome{}, 2)["delivery"]; got != agent.DeliveryQueued {
		t.Fatal(got)
	}
	if got := tickSummary(agent.Outcome{}, 0)["delivery"]; got != agent.DeliveryUploaded {
		t.Fatal(got)
	}
}
