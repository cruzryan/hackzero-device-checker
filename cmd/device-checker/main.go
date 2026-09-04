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
	"time"

	"github.com/hackzero/device-checker/internal/agent"
	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/pairing"
	"github.com/hackzero/device-checker/internal/posture"
	"github.com/hackzero/device-checker/internal/probe"
	"github.com/hackzero/device-checker/internal/reporting"
)

var version = "dev"

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
		runAgent(true, os.Args[2:])
	case "run":
		runAgent(false, os.Args[2:])
	case "connection":
		printConnection()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: device-checker <status|pair|report|run|connection>")
	os.Exit(2)
}

func printStatus() {
	observation, err := probe.Collect()
	if err != nil {
		// A collection error is not evidence of failure.
		observation = posture.Observation{}
	}
	// Architecture is intentionally not collected: it is not needed to prove a
	// posture setting.  `runtime.GOOS` is the honest platform value until each
	// platform probe supplies an OS release from an authoritative API.
	report := posture.Evaluate(observation, runtime.GOOS, runtime.GOOS, version, time.Now())
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type savedState struct {
	Identity      identity.Device `json:"identity"`
	ReportURL     string          `json:"report_url"`
	WorkspaceName string          `json:"workspace_name"`
	PersonName    string          `json:"person_name"`
}

func statePath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "HackZero", "DeviceChecker", "identity.json")
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

func loadState() (savedState, error) {
	device, err := identity.Load(statePath())
	if err != nil {
		return savedState{}, fmt.Errorf("load device identity: %w", err)
	}
	data, err := os.ReadFile(statePath() + ".pairing")
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
	payload := map[string]string{"device_id": device.ID, "public_key": device.PublicKey, "platform": runtime.GOOS, "device_name": *name, "redirect_uri": callbackURL, "state": session.State}
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
	if err := postJSON(trimServer(*server)+"/api/trust/device-checker/exchange", map[string]string{"code": result.Code, "device_id": device.ID}, &completed); err != nil {
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

func sendReport(args []string) {
	runAgent(true, args)
}

type reportSender struct{ url string }

func (s reportSender) Send(ctx context.Context, envelope reporting.Envelope) error {
	return postJSONContext(ctx, s.url, envelope, &map[string]any{})
}

func agentStatePath() string { return filepath.Join(filepath.Dir(statePath()), "agent-state.json") }
func spoolPath() string      { return filepath.Join(filepath.Dir(statePath()), "queue") }

func configuredRunner() (agent.Runner, error) {
	state, err := loadState()
	if err != nil {
		return agent.Runner{}, err
	}
	return agent.Runner{
		Device:    state.Identity,
		Collector: probe.Collect,
		Sender:    reportSender{url: state.ReportURL},
		Spool:     reporting.Spool{Directory: spoolPath(), MaxItems: 96},
		StatePath: agentStatePath(),
		Version:   version,
	}, nil
}

// run starts the durable background loop. Service managers start this command
// at boot; `run --once` is useful to test the installed runtime without a
// resident process. `report` remains a convenient one-shot Check now alias.
func runAgent(forceFull bool, args []string) {
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	once := flags.Bool("once", false, "run one scheduling tick and exit")
	_ = flags.Parse(args)
	runner, err := configuredRunner()
	if err != nil {
		fatal(err)
	}
	for {
		due, err := runner.Tick(context.Background(), forceFull)
		if err != nil {
			fatal(err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"full_report_due": due.FullReport, "heartbeat_due": due.Heartbeat})
		if *once || forceFull {
			return
		}
		forceFull = false
		time.Sleep(time.Minute)
	}
}

func postJSON(url string, input, output any) error {
	return postJSONContext(context.Background(), url, input, output)
}

func postJSONContext(ctx context.Context, url string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 64*1024)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(limited)
		return fmt.Errorf("server returned %s: %s", response.Status, string(data))
	}
	err = json.NewDecoder(limited).Decode(output)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
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
