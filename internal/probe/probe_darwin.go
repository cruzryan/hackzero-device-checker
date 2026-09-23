//go:build darwin

package probe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

const (
	softwareUpdatePlist        = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
	managedSoftwareUpdatePlist = "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist"
	managedPreferencesDir      = "/Library/Managed Preferences"
	xprotectInfoPlist          = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
	commandTimeout             = 20 * time.Second
)

// collect uses documented macOS command-line status interfaces, run as the
// logged-in user. A command that is absent, denied, or ambiguous leaves its
// signal unknown; it never turns an inconclusive response into a passing
// result. Parsing lives in pure helpers (darwin_parse.go) so it can be
// unit-tested without macOS.
func collect() (posture.Observation, error) {
	in := macInputs{
		ProductVersion: commandOutput("/usr/bin/sw_vers", "-productVersion"),
		FileVault:      commandOutput("/usr/bin/fdesetup", "status"),
		ConsoleSession: inConsoleSession(),
		Schedule:       commandOutput("/usr/sbin/softwareupdate", "--schedule"),
		Spctl:          commandOutput("/usr/sbin/spctl", "--status"),
		XProtect:       commandOutput("/usr/bin/xprotect", "version"),
	}
	if in.ConsoleSession {
		in.PmsetCustom = commandOutput("/usr/bin/pmset", "-g", "custom")
		in.PmsetBatt = commandOutput("/usr/bin/pmset", "-g", "batt")
		in.Sysadminctl = commandOutput("/usr/sbin/sysadminctl", "-screenLock", "status")
		// Exits 1 with "does not exist" when unset: keep that output.
		in.ScreensaverIdle = commandOutputAnyExit("/usr/bin/defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime")
		in.ManagedScreensaver = managedScreensaver()
	}
	local, localErr := readPlist(softwareUpdatePlist)
	switch {
	case localErr == nil:
		in.SoftwareUpdate = local
	case errors.Is(localErr, os.ErrNotExist):
		// No preferences file: every key is at its default (on).
		in.SoftwareUpdate = map[string]any{}
	}
	if managed, err := readPlist(managedSoftwareUpdatePlist); err == nil {
		in.ManagedSoftwareUpdate = managed
	}
	if in.XProtect == nil {
		in.XProtectVersion = commandOutput("/usr/bin/defaults", "read", xprotectInfoPlist, "CFBundleShortVersionString")
	}
	return macObservation(in, time.Now()), nil
}

func osVersion() string {
	if output := commandOutput("/usr/bin/sw_vers", "-productVersion"); output != nil {
		return posture.SanitizeToken(strings.TrimSpace(*output))
	}
	return ""
}

// inConsoleSession reports whether this process belongs to the user who owns
// the GUI console (/dev/console). Screen-lock settings are per user.
func inConsoleSession() bool {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return consoleSession(stat.Uid, uint32(os.Getuid()))
}

// managedScreensaver returns an MDM-forced screen-saver payload, user level
// first, then device level, or nil when none is installed.
func managedScreensaver() map[string]any {
	var paths []string
	if current, err := user.Current(); err == nil && current.Username != "" && !strings.ContainsAny(current.Username, `/\`) {
		paths = append(paths, filepath.Join(managedPreferencesDir, current.Username, "com.apple.screensaver.plist"))
	}
	paths = append(paths, filepath.Join(managedPreferencesDir, "com.apple.screensaver.plist"))
	for _, path := range paths {
		if plist, err := readPlist(path); err == nil {
			return plist
		}
	}
	return nil
}

// readPlist converts a property list with Apple's plutil, trying JSON first
// and falling back to XML for plists holding dates or data.
func readPlist(path string) (map[string]any, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	if output, err := run("/usr/bin/plutil", "-convert", "json", "-o", "-", path); err == nil {
		if plist, err := decodePlistJSON(output); err == nil {
			return plist, nil
		}
	}
	output, err := run("/usr/bin/plutil", "-convert", "xml1", "-o", "-", path)
	if err != nil {
		return nil, err
	}
	return decodePlistXML(output)
}

func run(binary string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, binary, args...).Output()
}

// commandOutput runs a read-only status command and returns its combined
// output, or nil if the command could not be executed or failed. Combined
// output is used so a status line printed on stderr is still observed.
func commandOutput(binary string, args ...string) *string {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	if err != nil {
		return nil
	}
	text := string(output)
	return &text
}

// commandOutputAnyExit is commandOutput for commands whose non-zero exit
// carries meaning (for example `defaults read` of an unset key). It returns
// nil only when the command could not start or timed out.
func commandOutputAnyExit(binary string, args ...string) *string {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && (!errors.As(err, &exitErr) || ctx.Err() != nil) {
		return nil
	}
	text := string(output)
	return &text
}
