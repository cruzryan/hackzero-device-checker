//go:build windows

package probe

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

// Elevated is intentionally narrow: this collector only needs elevation to
// read protected Windows posture APIs. It never uses that privilege to alter
// local configuration.
func Elevated() bool {
	output, err := powershell(30*time.Second, "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
	return err == nil && strings.EqualFold(strings.TrimSpace(string(output)), "True")
}

// collect runs the fixed, read-only windowsScript (windows_parse.go) and maps
// its JSON to posture facts. Every signal stays unknown when Windows does not
// expose an authoritative value on the machine.
func collect() (posture.Observation, error) {
	output, err := powershell(90*time.Second, windowsScript)
	if err != nil {
		return posture.Observation{}, err
	}
	raw, err := parseWindowsJSON(output)
	if err != nil {
		return posture.Observation{}, err
	}
	return raw.observation(time.Now()), nil
}

func osVersion() string {
	output, err := powershell(30*time.Second, `$v=[Environment]::OSVersion.Version; '{0}.{1}.{2}' -f $v.Major,$v.Minor,$v.Build`)
	if err != nil {
		return ""
	}
	return posture.SanitizeToken(strings.TrimSpace(string(output)))
}

func powershell(timeout time.Duration, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
}
