//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("Device Checker desktop UI preview is currently available on Windows. Run `device-checker status` for the local read-only report.")
}
