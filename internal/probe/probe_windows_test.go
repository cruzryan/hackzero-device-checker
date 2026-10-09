//go:build windows

package probe

import (
	"context"
	"testing"
)

// The desktop collector is a GUI-subsystem binary; a powershell.exe child
// without CREATE_NO_WINDOW flashes a visible console on every check.
func TestPowerShellNeverShowsAWindow(t *testing.T) {
	command := powershellCommand(context.Background(), "$true")
	if command.SysProcAttr == nil || command.SysProcAttr.CreationFlags&createNoWindow == 0 || !command.SysProcAttr.HideWindow {
		t.Fatalf("powershell.exe must start with CREATE_NO_WINDOW and a hidden window, got %+v", command.SysProcAttr)
	}
}
