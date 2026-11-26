package monotime

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// smallestStep spins for about 100 ms and returns the smallest amount by
// which consecutive readings of clock differed: the clock's granularity as a
// caller sees it.
func smallestStep(clock func() int64) time.Duration {
	smallest := time.Duration(1<<63 - 1)
	last := clock()
	// The wall clock ends the loop whatever granularity it has.
	for end := time.Now().Add(100 * time.Millisecond); time.Now().Before(end); {
		now := clock()
		if d := time.Duration(now - last); d > 0 {
			smallest = min(smallest, d)
			last = now
		}
	}
	return smallest
}

func TestCounterNanos(t *testing.T) {
	const tenMHz = 10_000_000
	require.Equal(t, int64(0), counterNanos(0, tenMHz))
	require.Equal(t, int64(100), counterNanos(1, tenMHz))
	require.Equal(t, int64(time.Second), counterNanos(tenMHz, tenMHz))
	// A week of ticks, which a single multiplication by a billion overflows.
	week := int64(7 * 24 * time.Hour / time.Second)
	require.Equal(t, week*int64(time.Second)+300, counterNanos(week*tenMHz+3, tenMHz))
	// A frequency that does not divide a billion.
	require.Equal(t, int64(time.Second)+333_333_333, counterNanos(4, 3))
}

func TestHighResolutionClock(t *testing.T) {
	t.Cleanup(func() { highRes.Store(false) })
	goClock := smallestStep(func() int64 { return int64(Now()) })
	t.Logf("%s: Now advances in steps of %v on Go's clock", runtime.GOOS, goClock)

	before := Now()
	enabled := UseHighResolutionClock()
	after := Now()
	require.Equal(t, runtime.GOOS == "windows", enabled)
	// The switch neither goes back nor jumps: the counter continues from
	// the value Now had.
	require.False(t, after.Before(before))
	require.Less(t, after.Sub(before), time.Second)
	if !enabled {
		return
	}
	require.True(t, UseHighResolutionClock(), "a second call reports the clock already in use")

	step := smallestStep(func() int64 { return int64(Now()) })
	t.Logf("%s: Now advances in steps of %v on the performance counter", runtime.GOOS, step)
	require.Less(t, step, 100*time.Microsecond)

	// It runs at the rate of Go's clock, and never backwards.
	start, goStart := Now(), time.Now()
	last := start
	for time.Since(goStart) < 200*time.Millisecond {
		now := Now()
		require.False(t, now.Before(last))
		last = now
	}
	require.InDelta(t, time.Since(goStart).Seconds(), last.Sub(start).Seconds(), 0.05)
	// Conversions stay within a clock interrupt of Go's clock.
	require.InDelta(t, 0, time.Until(Now().ToTime()).Seconds(), 0.05)
	require.InDelta(t, 0, Until(FromTime(time.Now())).Seconds(), 0.05)
}
