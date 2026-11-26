//go:build windows

package monotime

import (
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerformanceCounter   = kernel32.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = kernel32.NewProc("QueryPerformanceFrequency")
)

// The counter's reading and Now's value when the switch was made, and the
// counter's frequency in ticks per second.
var (
	highResOnce      sync.Once
	highResOK        bool
	highResCounter   int64
	highResBase      int64
	highResFrequency int64
)

func queryPerformanceCounter() int64 {
	var counter int64
	// The call cannot fail on Windows XP or later.
	_, _, _ = syscall.SyscallN(procQueryPerformanceCounter.Addr(), uintptr(unsafe.Pointer(&counter)))
	return counter
}

// startHighRes anchors the counter at base, the value Now has at this moment.
func startHighRes(base int64) bool {
	highResOnce.Do(func() {
		if procQueryPerformanceCounter.Find() != nil || procQueryPerformanceFrequency.Find() != nil {
			return
		}
		var frequency int64
		_, _, _ = syscall.SyscallN(procQueryPerformanceFrequency.Addr(), uintptr(unsafe.Pointer(&frequency)))
		if frequency <= 0 {
			return
		}
		highResFrequency, highResBase, highResCounter = frequency, base, queryPerformanceCounter()
		highResOK = true
	})
	return highResOK
}

func highResNow() int64 {
	return highResBase + counterNanos(queryPerformanceCounter()-highResCounter, highResFrequency)
}
