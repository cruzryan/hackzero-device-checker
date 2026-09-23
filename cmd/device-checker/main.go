package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hackzero/device-checker/internal/agent"
	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/pairing"
	"github.com/hackzero/device-checker/internal/posture"
	"github.com/hackzero/device-checker/internal/probe"
	"github.com/hackzero/device-checker/internal/reporting"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

// lockWait is how long a second run waits for the running one to finish.
const lockWait = 20 * time.Second

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "status":
		printStatus()
	case "pair":
		pairDevice(os.Args[2:])
	case "report":
		sendReport()
	case "run":
		runAgent(os.Args[2:])
	case "last":
		_, _ = os.Stdout.Write(append(lastOutput(stateDir()), '\n'))
	case "diagnose":
		printJSON(buildDiagnosis(stateDir(), probe.OSVersion()))
	case "connection":
		printConnection()
	case "disconnect":
		disconnectDevice()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: device-checker <status|report|run [--once]|last|diagnose|pair|connection|disconnect>")
	os.Exit(2)
}

func requireElevation() {
	if runtime.GOOS == "windows" && !probe.Elevated() {
		failJSON("elevation_required", "administrator approval is required to collect Windows posture", 3)
	}
}

// printStatus collects and prints the Report. It is never sent.
func printStatus() {
	requireElevation()
	observation, err := probe.Collect()
	if err != nil {
		// A collection error is not evidence of failure.
		observation = posture.Observation{}
	}
	printJSON(posture.Evaluate(observation, runtime.GOOS, "", version, time.Now()))
}

type savedState struct {
	Identity      identity.Device `json:"identity"`
	ReportURL     string          `json:"report_url"`
	WorkspaceName string          `json:"workspace_name"`
	PersonName    string          `json:"person_name"`
}

// stateDir holds the identity, pairing, scheduler state, queue, last report
// and lock file. Everything in it is owner-only.
func stateDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "HackZero", "DeviceChecker")
}

func statePath() string                { return identityPath(stateDir()) }
func identityPath(dir string) string   { return filepath.Join(dir, "identity.json") }
func pairingPath(dir string) string    { return identityPath(dir) + ".pairing" }
func agentStatePath(dir string) string { return filepath.Join(dir, "agent-state.json") }
func spoolPath(dir string) string      { return filepath.Join(dir, "queue") }
func lastReportPath(dir string) string { return filepath.Join(dir, "last-report.json") }
func lockPath(dir string) string       { return filepath.Join(dir, "device-checker.lock") }
func spoolFor(dir string) reporting.Spool {
	return reporting.Spool{Directory: spoolPath(dir), MaxItems: 96}
}

func loadOrCreateIdentity() (identity.Device, error) {
	path := statePath()
	if saved, err := identity.Load(path); err == nil {
		return saved, nil
	}
	created, err := identity.New()
	if err != nil {
		return identity.Device{}, err
	}
	if err := created.Save(path); err != nil {
		return identity.Device{}, err
	}
	return created, nil
}

func loadState() (savedState, error) { return loadStateFrom(stateDir()) }

func loadStateFrom(dir string) (savedState, error) {
	device, err := identity.Load(identityPath(dir))
	if err != nil {
		return savedState{}, fmt.Errorf("load device identity: %w", err)
	}
	data, err := os.ReadFile(pairingPath(dir))
	if err != nil {
		return savedState{}, errors.New("this device is not connected to HackZero")
	}
	var state savedState
	if err := json.Unmarshal(data, &state); err != nil {
		return savedState{}, fmt.Errorf("read pairing state: %w", err)
	}
	if state.Identity.ID != device.ID || state.ReportURL == "" {
		return savedState{}, errors.New("invalid pairing state")
	}
	// Private material is loaded only from the protected identity file; it is
	// deliberately not duplicated into the pairing-state JSON.
	state.Identity = device
	return state, nil
}

func saveState(state savedState) error {
	path := statePath() + ".pairing"
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func pairDevice(args []string) {
	flags := flag.NewFlagSet("pair", flag.ExitOnError)
	server := flags.String("server", "https://dashboard.hackzero.ai", "HackZero server URL")
	name := flags.String("name", hostname(), "device name")
	_ = flags.Parse(args)
	device, err := loadOrCreateIdentity()
	if err != nil {
		fatal(err)
	}
	session, err := pairing.NewSession()
	if err != nil {
		fatal(err)
	}
	listener, callbackURL, err := pairing.StartLoopback(session)
	if err != nil {
		fatal(err)
	}
	payload := map[string]string{"device_id": device.ID, "public_key": device.PublicKey, "platform": runtime.GOOS, "device_name": *name, "redirect_uri": callbackURL, "state": session.State, "code_challenge": session.Challenge()}
	var started struct {
		ApprovalURL string `json:"approval_url"`
	}
	if err := postJSON(trimServer(*server)+"/api/trust/device-checker/pairings", payload, &started); err != nil {
		listener.Close()
		fatal(err)
	}
	if started.ApprovalURL == "" {
		listener.Close()
		fatal(errors.New("server did not return an approval URL"))
	}
	if err := openBrowser(started.ApprovalURL); err != nil {
		listener.Close()
		fatal(err)
	}
	result := listener.Wait(context.Background())
	if result.Err != nil {
		fatal(result.Err)
	}
	var completed struct {
		ReportURL     string `json:"report_url"`
		WorkspaceName string `json:"workspace_name"`
		PersonName    string `json:"person_name"`
	}
	if err := postJSON(trimServer(*server)+"/api/trust/device-checker/exchange", map[string]string{"code": result.Code, "device_id": device.ID, "code_verifier": session.Verifier}, &completed); err != nil {
		fatal(err)
	}
	if completed.ReportURL == "" {
		fatal(errors.New("server did not return a report URL"))
	}
	if err := saveState(savedState{Identity: device, ReportURL: completed.ReportURL, WorkspaceName: completed.WorkspaceName, PersonName: completed.PersonName}); err != nil {
		fatal(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"paired": true, "report_url": completed.ReportURL, "workspace_name": completed.WorkspaceName, "person_name": completed.PersonName})
}

func printConnection() {
	state, err := loadState()
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"paired": false})
		return
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"paired": true, "workspace_name": state.WorkspaceName, "person_name": state.PersonName})
}

// disconnectDevice deliberately has no browser authority. It asks the service
// to revoke this device's registration by signing a short-lived challenge, then
// clears local pairing. Clearing this device's OWN local state needs no server
// permission, so if the service no longer has an active registration (the device
// was already deactivated), disconnect still succeeds and cleans up locally
// instead of trapping the user as connected. Only a genuine transport failure
// keeps local state so the user can retry.
func disconnectDevice() {
	state, err := loadState()
	if err != nil {
		// Nothing is connected locally (or the pairing is unreadable); make sure
		// no stale files remain and report success so the UI settles unpaired.
		removeLocalPairing()
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"disconnected": true})
		return
	}
	if err := revokeServerRegistration(state); err != nil && !serverForgotDevice(err) {
		fatal(err)
	}
	removeLocalPairing()
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"disconnected": true})
}

// revokeServerRegistration performs the signed disconnect handshake so the
// service stops accepting this device's reports.
func revokeServerRegistration(state savedState) error {
	base := strings.TrimSuffix(state.ReportURL, "/reports")
	var challenge struct {
		Nonce string `json:"nonce"`
	}
	if err := postJSON(base+"/disconnect/challenge", map[string]string{"device_id": state.Identity.ID}, &challenge); err != nil {
		return err
	}
	if challenge.Nonce == "" {
		return errors.New("server did not return a disconnect challenge")
	}
	// Field declaration order is part of the canonical signed message contract.
	unsigned := struct {
		DeviceID string `json:"device_id"`
		Nonce    string `json:"nonce"`
	}{DeviceID: state.Identity.ID, Nonce: challenge.Nonce}
	message, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	signature, err := state.Identity.Sign(message)
	if err != nil {
		return err
	}
	return postJSON(base+"/disconnect", map[string]string{
		"device_id": state.Identity.ID, "nonce": challenge.Nonce, "signature": signature,
	}, &map[string]any{})
}

// serverForgotDevice reports whether the error means the service has no active
// registration for this device, so there is nothing left to revoke.
func serverForgotDevice(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		return he.status == http.StatusUnauthorized ||
			he.status == http.StatusNotFound ||
			he.status == http.StatusGone
	}
	return false
}

// removeLocalPairing clears this device's pairing and identity so a later
// pairing uses a fresh key rather than one the service may have revoked. It is
// best effort: a leftover file must not block the user from disconnecting.
func removeLocalPairing() {
	_ = os.Remove(statePath() + ".pairing")
	_ = os.Remove(statePath())
}

// reportSender posts a signed envelope and captures the service's verdict.
type reportSender struct{ url string }

func (s reportSender) Send(ctx context.Context, envelope reporting.Envelope) (agent.SendResult, error) {
	var response struct {
		Device *agent.ServerDevice `json:"device"`
	}
	status, err := postJSONStatus(ctx, s.url, envelope, &response)
	var he *httpError
	switch {
	case errors.As(err, &he):
		return agent.SendResult{HTTPStatus: he.status, ErrorCode: serverErrorCode(he.body)}, err
	case status == 0:
		return agent.SendResult{}, err
	default:
		// A 2xx whose body could not be decoded was still accepted.
		return agent.SendResult{HTTPStatus: status, Device: response.Device}, nil
	}
}

// serverErrorCode extracts the service's short {"error": "..."} code.
func serverErrorCode(body string) string {
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(body), &parsed) != nil {
		return ""
	}
	return posture.SanitizeToken(parsed.Error)
}

func configuredRunner(dir string) (agent.Runner, error) {
	state, err := loadStateFrom(dir)
	if err != nil {
		return agent.Runner{}, err
	}
	return agent.Runner{
		Device:         state.Identity,
		Collector:      probe.Collect,
		Sender:         reportSender{url: state.ReportURL},
		Spool:          spoolFor(dir),
		StatePath:      agentStatePath(dir),
		LastReportPath: lastReportPath(dir),
		Version:        version,
	}, nil
}

// sendReport collects, signs and sends ONE full report ("Check now"), prints
// its RunResult, and persists it as last-report.json.
func sendReport() {
	requireElevation()
	dir := stateDir()
	runner, err := configuredRunner(dir)
	if err != nil {
		failJSON("not_connected", err.Error(), 1)
	}
	runner.Source = agent.SourceManual
	release, err := agent.AcquireLock(lockPath(dir), lockWait)
	if err != nil {
		failLock(err)
	}
	outcome, err := runner.Run(context.Background(), true)
	release()
	if err != nil {
		failJSON("report_failed", err.Error(), 1)
	}
	if outcome.Full == nil {
		failJSON("report_failed", "no full report was produced", 1)
	}
	printJSON(outcome.Full)
}

// runAgent starts the durable background loop. Service managers start this
// command at boot; `run --once` performs one scheduling tick and exits. Each
// tick holds the lock so it never overlaps a manual `report`.
func runAgent(args []string) {
	requireElevation()
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	once := flags.Bool("once", false, "run one scheduling tick and exit")
	_ = flags.Parse(args)
	dir := stateDir()
	runner, err := configuredRunner(dir)
	if err != nil {
		fatal(err)
	}
	runner.Source = agent.SourceBackground
	for {
		release, err := agent.AcquireLock(lockPath(dir), lockWait)
		if err != nil {
			if *once || !errors.Is(err, agent.ErrBusy) {
				failLock(err)
			}
			time.Sleep(time.Minute)
			continue
		}
		outcome, err := runner.Run(context.Background(), false)
		release()
		if err != nil {
			fatal(err)
		}
		printJSON(tickSummary(outcome, runner.Spool.Count()))
		if *once {
			return
		}
		time.Sleep(time.Minute)
	}
}

// tickSummary is the `run` output line.
func tickSummary(outcome agent.Outcome, queued int) map[string]any {
	delivery := agent.DeliveryUploaded
	switch {
	case outcome.Full != nil:
		delivery = outcome.Full.Delivery
	case outcome.HeartbeatDelivery != "":
		delivery = outcome.HeartbeatDelivery
	case queued > 0:
		delivery = agent.DeliveryQueued
	}
	return map[string]any{"full_report_due": outcome.Due.FullReport, "heartbeat_due": outcome.Due.Heartbeat, "delivery": delivery}
}

// lastOutput is last-report.json verbatim, or {"available": false}.
func lastOutput(dir string) []byte {
	data, err := os.ReadFile(lastReportPath(dir))
	if err != nil || !json.Valid(data) {
		return []byte(`{"available":false}`)
	}
	var compact bytes.Buffer
	if json.Compact(&compact, data) != nil {
		return []byte(`{"available":false}`)
	}
	return compact.Bytes()
}

// diagnosis is support information. It never contains the private key or the
// identity file: only the public device id.
type diagnosis struct {
	CheckerVersion string          `json:"checker_version"`
	OSVersion      string          `json:"os_version"`
	Platform       string          `json:"platform"`
	Paired         bool            `json:"paired"`
	WorkspaceName  string          `json:"workspace_name"`
	PersonName     string          `json:"person_name"`
	DeviceID       string          `json:"device_id"`
	AgentState     *agent.State    `json:"agent_state"`
	QueueCount     int             `json:"queue_count"`
	Last           json.RawMessage `json:"last"`
}

func buildDiagnosis(dir, osVersion string) diagnosis {
	d := diagnosis{
		CheckerVersion: posture.SanitizeToken(version),
		OSVersion:      posture.SanitizeToken(osVersion),
		Platform:       runtime.GOOS,
		QueueCount:     spoolFor(dir).Count(),
	}
	if state, err := loadStateFrom(dir); err == nil {
		d.Paired, d.WorkspaceName, d.PersonName, d.DeviceID = true, state.WorkspaceName, state.PersonName, state.Identity.ID
	} else if device, err := identity.Load(identityPath(dir)); err == nil {
		d.DeviceID = device.ID
	}
	if _, err := os.Stat(agentStatePath(dir)); err == nil {
		state := agent.LoadState(agentStatePath(dir))
		d.AgentState = &state
	}
	if last := lastOutput(dir); !bytes.Equal(last, []byte(`{"available":false}`)) {
		d.Last = last
	}
	return d
}

func printJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fatal(err)
	}
}

// failJSON prints a machine-readable error on stdout (the desktop app reads
// stdout) and a readable line on stderr, then exits.
func failJSON(code, message string, exitCode int) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": code, "message": message})
	fmt.Fprintln(os.Stderr, "device-checker:", message)
	os.Exit(exitCode)
}

func failLock(err error) {
	if errors.Is(err, agent.ErrBusy) {
		failJSON("busy", "Another Device Checker check is already running. Try again in a moment.", 4)
	}
	failJSON("lock_failed", err.Error(), 1)
}

// httpError carries a non-2xx server response so callers can branch on the
// status code (for example, treating 401/404 on disconnect as "already gone")
// without matching on the response text.
type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.status, e.body)
}

func postJSON(url string, input, output any) error {
	_, err := postJSONStatus(context.Background(), url, input, output)
	return err
}

// postJSONStatus returns the HTTP status (0 when no response arrived). A 2xx
// whose body does not decode returns the status and the decode error.
func postJSONStatus(ctx context.Context, url string, input, output any) (int, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 64*1024)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(limited)
		return response.StatusCode, &httpError{status: response.StatusCode, body: string(data)}
	}
	err = json.NewDecoder(limited).Decode(output)
	if errors.Is(err, io.EOF) {
		return response.StatusCode, nil
	}
	return response.StatusCode, err
}

func trimServer(server string) string {
	for len(server) > 0 && server[len(server)-1] == '/' {
		server = server[:len(server)-1]
	}
	return server
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "This device"
	}
	return name
}

func openBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		command = exec.Command("open", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	return command.Start()
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "device-checker:", err); os.Exit(1) }
