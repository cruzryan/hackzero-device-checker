package probe

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

// TestLiveProbe runs the real platform probe and logs the report it would
// send. It is opt-in (DEVICE_CHECKER_LIVE=1) because it reads this machine.
func TestLiveProbe(t *testing.T) {
	if os.Getenv("DEVICE_CHECKER_LIVE") != "1" {
		t.Skip("set DEVICE_CHECKER_LIVE=1 to read this machine")
	}
	started := time.Now()
	observation, err := Collect()
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	report := posture.Evaluate(observation, runtime.GOOS, "", "dev", time.Now())
	data, _ := json.MarshalIndent(report, "", "  ")
	t.Logf("collected in %s (os version %q)\n%s", time.Since(started).Round(time.Millisecond), OSVersion(), data)
}
