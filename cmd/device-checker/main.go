// device-checker is intentionally limited to local posture evaluation. Network
// pairing and reporting are added only when their server contract is complete.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

var version = "dev"

func main() {
	if len(os.Args) != 2 || os.Args[1] != "status" {
		fmt.Fprintln(os.Stderr, "usage: device-checker status")
		os.Exit(2)
	}
	// This deliberately reports unknown local posture until an OS-specific
	// read-only probe is present. It must never manufacture a compliance pass.
	report := posture.Evaluate(posture.Observation{}, runtime.GOOS, runtime.GOARCH, version, time.Now())
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
