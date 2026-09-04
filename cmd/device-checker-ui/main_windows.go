//go:build windows

// device-checker-ui is deliberately a native, lightweight status surface. It
// uses WPF already present on supported Windows versions; no browser runtime,
// Electron bundle, or embedded account credential is needed.
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

type screenRow struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Status string `json:"status"`
}

type screenModel struct {
	Title       string      `json:"title"`
	Description string      `json:"description"`
	CheckedAt   string      `json:"checkedAt"`
	Rows        []screenRow `json:"rows"`
}

func main() {
	model := collect()
	payload, err := json.Marshal(model)
	if err != nil {
		panic(err)
	}
	// Data travels as base64 JSON so a device-provided value is never treated as
	// PowerShell source. The only script executed is the constant below.
	encoded := base64.StdEncoding.EncodeToString(utf16LE("& { param($json) " + windowsForm + " } '" + base64.StdEncoding.EncodeToString(payload) + "'"))
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded)
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
		Title:       "Your device, in view.",
		Description: "A private, read-only check of the security settings that protect your work.",
		CheckedAt:   "Checked on this device · " + report.CollectedAt.Local().Format("Jan 2, 2006 at 3:04 PM"),
	}
	for _, item := range signals {
		model.Rows = append(model.Rows, screenRow{Label: item.label, Value: displaySignal(item.signal), Status: string(item.signal.Status)})
	}
	return model
}

func displaySignal(signal posture.Signal) string {
	switch signal.Status {
	case posture.Pass:
		return "Protected"
	case posture.NeedsAttention:
		return "Review needed · updates are pending"
	case posture.Fail:
		return "Review needed · " + strings.ReplaceAll(signal.Code, "_", " ")
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

const windowsForm = `
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
$data = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($json)) | ConvertFrom-Json
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="HackZero Device Checker" Width="820" Height="690" WindowStartupLocation="CenterScreen"
        Background="#F8F6F2" ResizeMode="NoResize" FontFamily="Segoe UI">
  <Border Margin="14" BorderBrush="#DED9D0" BorderThickness="1" Background="#FFFDFC" CornerRadius="3">
    <Grid Margin="42,34,42,32">
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <StackPanel Grid.Row="0" Grid.Column="0">
        <StackPanel Orientation="Horizontal"><TextBlock Text="HACKZERO" FontSize="12" FontWeight="SemiBold" Foreground="#171717"/><Ellipse Width="7" Height="7" Margin="8,5,0,0" Fill="#2785D7"/></StackPanel>
        <TextBlock x:Name="Heading" Margin="0,30,0,8" FontFamily="Georgia" FontSize="42" Foreground="#151515"/>
        <TextBlock x:Name="Description" Width="570" FontSize="16" Foreground="#595653" TextWrapping="Wrap" LineHeight="25"/>
      </StackPanel>
      <Border Grid.Row="0" Grid.Column="1" Background="#E9F4EC" BorderBrush="#BEDAC6" BorderThickness="1" CornerRadius="20" Padding="14,7" VerticalAlignment="Top"><TextBlock Text="READ-ONLY" FontSize="11" FontWeight="SemiBold" Foreground="#28653B"/></Border>
      <StackPanel x:Name="Checks" Grid.Row="2" Grid.ColumnSpan="2" Margin="0,34,0,24"/>
      <Grid Grid.Row="3" Grid.ColumnSpan="2"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <TextBlock x:Name="CheckedAt" VerticalAlignment="Center" FontSize="13" Foreground="#77716C"/>
        <Button x:Name="Refresh" Grid.Column="1" Content="Check again" Padding="20,10" Margin="0,0,14,0" Background="#FFFDFC" BorderBrush="#181818" BorderThickness="1" Foreground="#171717" FontSize="14" Cursor="Hand"/>
        <Button x:Name="Connect" Grid.Column="2" Content="Connect to HackZero  →" Padding="20,10" Background="#171717" BorderBrush="#171717" Foreground="White" FontSize="14" Cursor="Hand"/>
      </Grid>
    </Grid>
  </Border>
</Window>
'@
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
$window.FindName('Heading').Text = $data.Title
$window.FindName('Description').Text = $data.Description
$window.FindName('CheckedAt').Text = $data.CheckedAt
$checks = $window.FindName('Checks')
foreach ($row in $data.Rows) {
  $card = New-Object Windows.Controls.Border
  $card.BorderBrush = [Windows.Media.Brushes]::Transparent; $card.BorderThickness = '1'; $card.CornerRadius = '3'; $card.Margin = '0,0,0,9'; $card.Padding = '20,15'
  if ($row.Status -eq 'pass') { $card.Background = [Windows.Media.BrushConverter]::new().ConvertFromString('#F2F7F3') } elseif ($row.Status -eq 'unknown') { $card.Background = [Windows.Media.BrushConverter]::new().ConvertFromString('#F4F1ED') } else { $card.Background = [Windows.Media.BrushConverter]::new().ConvertFromString('#FFF1EF') }
  $grid = New-Object Windows.Controls.Grid
  $left = New-Object Windows.Controls.TextBlock; $left.Text = $row.Label; $left.FontSize = 16; $left.FontWeight = 'SemiBold'; $left.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString('#202020'); $left.VerticalAlignment = 'Center'; [void]$grid.Children.Add($left)
  $right = New-Object Windows.Controls.TextBlock; $right.Text = $row.Value; $right.FontSize = 14; $right.VerticalAlignment = 'Center'; $right.HorizontalAlignment = 'Right'
  if ($row.Status -eq 'pass') { $right.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString('#27683B') } elseif ($row.Status -eq 'unknown') { $right.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString('#766F68') } else { $right.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString('#B13E32') }; [void]$grid.Children.Add($right)
  $card.Child = $grid; [void]$checks.Children.Add($card)
}
$window.FindName('Refresh').Add_Click({
  # The GUI executable is launched hidden, so refresh never flashes a console.
  $window.Close()
  $start = New-Object System.Diagnostics.ProcessStartInfo
  $start.FileName = $env:HACKZERO_DEVICE_CHECKER_UI_PATH; $start.UseShellExecute = $true
  $start.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
  [System.Diagnostics.Process]::Start($start) | Out-Null
})
$window.FindName('Connect').Add_Click({ Start-Process 'https://hackzero.ai/device-checker' })
[void]$window.ShowDialog()
`
