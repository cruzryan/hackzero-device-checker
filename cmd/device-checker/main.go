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
	"github.com/hackzero/device-checker/internal/probe"
)

var version = "dev"

func main() {
	if len(os.Args) != 2 || os.Args[1] != "status" {
		fmt.Fprintln(os.Stderr, "usage: device-checker status")
		os.Exit(2)
	}
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
