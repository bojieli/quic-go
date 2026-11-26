//go:build !windows

package monotime

// Go's clock is fine-grained on these systems: there is nothing to switch to.
func startHighRes(int64) bool { return false }

func highResNow() int64 { panic("monotime: no high-resolution clock on this system") }
