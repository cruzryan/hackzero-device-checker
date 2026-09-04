//go:build windows

// device-checker-ui opens the normal-user Windows status window. The checker
// itself stays a small Go binary; Windows Forms is provided by the OS rather
// than embedding a browser engine or an Electron runtime.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/hackzero/device-checker/internal/posture"
	"github.com/hackzero/device-checker/internal/probe"
)

var version = "dev"

type screenModel struct {
	Title       string
	Description string
	CheckedAt   string
	Rows        []string
}

func main() {
	model := collect()
	payload, err := json.Marshal(model)
	if err != nil {
		panic(err)
	}
	// -EncodedCommand avoids quoting user/device data into a shell command.
	encoded := base64.StdEncoding.EncodeToString(utf16LE("& { param($json) " + windowsForm + " } '" + base64.StdEncoding.EncodeToString(payload) + "'"))
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded)
	// The refresh action relaunches this exact binary, including when it was
	// started from a temporary preview location rather than an installer path.
	if executable, executableErr := os.Executable(); executableErr == nil {
		command.Env = append(os.Environ(), "HACKZERO_DEVICE_CHECKER_UI_PATH="+executable)
	}
	if err := command.Run(); err != nil {
		panic(fmt.Errorf("open status window: %w", err))
	}
}

func collect() screenModel {
	observation, err := probe.Collect()
	if err != nil {
		observation = posture.Observation{}
	}
	report := posture.Evaluate(observation, runtime.GOOS, runtime.GOOS, version, time.Now())
	signals := []struct {
		label  string
		signal posture.Signal
	}{
		{"Disk encryption", report.DiskEncryption},
		{"Screen lock", report.ScreenLock},
		{"Automatic updates", report.AutomaticUpdates},
		{"Pending updates", report.PendingMaintenance},
		{"Endpoint protection", report.EndpointProtection},
	}
	model := screenModel{
		Title:       "This device is checked",
		Description: "Read-only posture checks. Nothing is sent until this device is paired.",
		CheckedAt:   "Checked locally: " + report.CollectedAt.Local().Format("Jan 2, 2006 at 3:04 PM"),
	}
	for _, item := range signals {
		model.Rows = append(model.Rows, item.label+"|"+displaySignal(item.signal))
		if item.signal.Status == posture.Fail || item.signal.Status == posture.NeedsAttention {
			model.Title = "This device needs attention"
		}
	}
	return model
}

func displaySignal(signal posture.Signal) string {
	switch signal.Status {
	case posture.Pass:
		return "Protected"
	case posture.NeedsAttention:
		return "Needs attention — updates are pending"
	case posture.Fail:
		return "Needs attention — " + strings.ReplaceAll(signal.Code, "_", " ")
	default:
		return "Not available on this device"
	}
}

func utf16LE(value string) []byte {
	encoded := utf16.Encode([]rune(value))
	bytes := make([]byte, len(encoded)*2)
	for index, value := range encoded {
		bytes[index*2], bytes[index*2+1] = byte(value), byte(value>>8)
	}
	return bytes
}

// windowsForm has no user-supplied code. It decodes JSON supplied by this
// process and uses it only as labels. Pairing deliberately opens the public
// account page instead of accepting a token in this preview.
const windowsForm = `
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$data = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($json)) | ConvertFrom-Json
$form = New-Object System.Windows.Forms.Form
$form.Text = 'HackZero Device Checker'
$form.Size = New-Object System.Drawing.Size(700,470)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [Drawing.Color]::White
$form.Font = New-Object Drawing.Font('Segoe UI', 10)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$title = New-Object System.Windows.Forms.Label
$title.Text = $data.Title; $title.Font = New-Object Drawing.Font('Segoe UI', 20, [Drawing.FontStyle]::Bold)
$title.AutoSize = $true; $title.Location = New-Object Drawing.Point(32,28); $form.Controls.Add($title)
$copy = New-Object System.Windows.Forms.Label
$copy.Text = $data.Description; $copy.AutoSize = $true; $copy.Location = New-Object Drawing.Point(34,74); $form.Controls.Add($copy)
$top = 115
foreach ($row in $data.Rows) {
  $parts = $row -split '\|', 2
  $box = New-Object System.Windows.Forms.Panel
  $box.BorderStyle = 'FixedSingle'; $box.Size = New-Object Drawing.Size(620,42); $box.Location = New-Object Drawing.Point(32,$top)
  $label = New-Object System.Windows.Forms.Label; $label.Text = $parts[0]; $label.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold); $label.AutoSize = $true; $label.Location = New-Object Drawing.Point(12,11)
  $value = New-Object System.Windows.Forms.Label; $value.Text = $parts[1]; $value.AutoSize = $true; $value.Location = New-Object Drawing.Point(330,11)
  if ($parts[1] -like 'Protected') { $value.ForeColor = [Drawing.Color]::FromArgb(24,115,67) } else { $value.ForeColor = [Drawing.Color]::FromArgb(160,33,33) }
  $box.Controls.Add($label); $box.Controls.Add($value); $form.Controls.Add($box); $top += 47
}
$checked = New-Object System.Windows.Forms.Label
$checked.Text = $data.CheckedAt; $checked.AutoSize = $true; $checked.ForeColor = [Drawing.Color]::DimGray; $checked.Location = New-Object Drawing.Point(34,360); $form.Controls.Add($checked)
$refresh = New-Object System.Windows.Forms.Button
$refresh.Text = 'Check again'; $refresh.Size = New-Object Drawing.Size(105,34); $refresh.Location = New-Object Drawing.Point(420,390)
$refresh.Add_Click({ $form.Close(); Start-Process -FilePath $env:HACKZERO_DEVICE_CHECKER_UI_PATH }); $form.Controls.Add($refresh)
$connect = New-Object System.Windows.Forms.Button
$connect.Text = 'Connect to HackZero'; $connect.Size = New-Object Drawing.Size(145,34); $connect.Location = New-Object Drawing.Point(535,390)
$connect.Add_Click({ Start-Process 'https://hackzero.ai'; [Windows.Forms.MessageBox]::Show('Sign-in and secure device pairing will be available here once the organization pairing service is enabled. This preview does not collect an account token.', 'Pairing is not enabled yet') }); $form.Controls.Add($connect)
[void]$form.ShowDialog()
`
