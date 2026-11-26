package monotime

import (
	"time"

	"github.com/apernet/quic-go/internal/monotime"
)

// A Time represents an instant in monotonic time.
// Times can be compared using the comparison operators, but the specific
// value is implementation-dependent and should not be relied upon.
// The zero value of Time doesn't have any specific meaning.
type Time = monotime.Time

// Now returns the current monotonic time.
func Now() Time {
	return monotime.Now()
}

// Since returns the time elapsed since t. It is shorthand for Now().Sub(t).
func Since(t Time) time.Duration {
	return monotime.Since(t)
}

// Until returns the duration until t.
// It is shorthand for t.Sub(Now()).
// If t is in the past, the returned duration will be negative.
func Until(t Time) time.Duration {
	return monotime.Until(t)
}

// FromTime converts a time.Time to a monotonic Time.
// The conversion is relative to the package's start time and may lose
// precision if the time.Time is far from the start time.
func FromTime(t time.Time) Time {
	return monotime.FromTime(t)
}

// UseHighResolutionClock makes Now read the operating system's
// high-resolution counter where Go's own clock is coarse, and reports
// whether it did. It has an effect on Windows only, where time.Now advances
// once per clock interrupt (15.6 ms by default): too coarse to time a round
// trip, a delivery-rate sample or a pacing interval on a short path.
//
// It is opt-in because a program that fakes time (testing/synctest) needs
// Now to follow the fake clock. Call it once at program start.
func UseHighResolutionClock() bool {
	return monotime.UseHighResolutionClock()
}
