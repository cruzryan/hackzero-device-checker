//go:build !windows

package probe

// The macOS and Linux collectors deliberately stay unprivileged. Their
// platform-specific privileged helpers will be introduced separately.
func Elevated() bool { return true }
