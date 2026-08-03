package main

import (
	"math"
	"math/rand"
	"strings"
	"time"
)

// Traffic shapes. `continuous` sends back-to-back periods; `periodic`/`burst`
// idle for one period between sends; `poisson` uses exponential inter-arrival
// times; `ramp` scales payload size from 10% to 100% across the period.
const (
	PatternContinuous = "continuous"
	PatternPeriodic   = "periodic"
	PatternBurst      = "burst"
	PatternPoisson    = "poisson"
	PatternRamp       = "ramp"
)

// ticksPerSecond is the pacing granularity. The Python senders used 20 Hz
// because interpreter overhead and sleep granularity made anything finer
// unreliable, which turned a "1 Mbps stream" into 20 bursts of ~52 KiB a
// second. A compiled agent can pace far tighter, so the rate configured in the
// scenario is closer to what actually appears on the wire.
const ticksPerSecond = 200

// defaultPeriodSeconds matches the original scripts' fallback.
const defaultPeriodSeconds = 10.0

func NormalizePattern(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case PatternPoisson:
		return PatternPoisson
	case PatternRamp:
		return PatternRamp
	case PatternBurst:
		return PatternBurst
	case PatternPeriodic:
		return PatternPeriodic
	default:
		return PatternContinuous
	}
}

// Pacer converts a flow's rate/period/jitter into a stream of send decisions.
type Pacer struct {
	pattern   string
	perTick   int
	tickSleep time.Duration
	period    time.Duration
	jitterPct float64
	rng       *rand.Rand
}

func NewPacer(pattern string, rateKbps, periodS, jitterPct float64, rng *rand.Rand) *Pacer {
	bps := rateKbps * 1024.0
	if bps <= 0 {
		bps = 1024.0 // ~1 KiB/s when a flow specifies no rate
	}
	perTick := int(bps / float64(ticksPerSecond))
	if perTick <= 0 {
		perTick = 1
	}
	period := time.Duration(defaultPeriodSeconds * float64(time.Second))
	if periodS > 0 {
		period = time.Duration(periodS * float64(time.Second))
	}
	if jitterPct < 0 {
		jitterPct = 0
	}
	return &Pacer{
		pattern:   NormalizePattern(pattern),
		perTick:   perTick,
		tickSleep: time.Duration(float64(time.Second) / float64(ticksPerSecond)),
		period:    period,
		jitterPct: jitterPct,
		rng:       rng,
	}
}

// JitterDelay applies the flow's jitter percentage to a base delay, uniformly
// within +/- jitter, never returning a negative duration.
func (p *Pacer) JitterDelay(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	if p.jitterPct <= 0 {
		return base
	}
	b := float64(base)
	j := b * (p.jitterPct / 100.0)
	d := b - j + p.rng.Float64()*2*j
	if d < 0 {
		return 0
	}
	return time.Duration(d)
}

// Step is one send decision: how many bytes, then how long to wait.
type Step struct {
	Size  int
	Delay time.Duration
}

// Steps produces the sends for a single period. `elapsed` is measured from the
// start of the period so `ramp` can scale with it.
func (p *Pacer) Step(elapsed time.Duration) Step {
	switch p.pattern {
	case PatternPoisson:
		// Exponential payload size and exponential inter-arrival, matching the
		// original random.expovariate(1/mean) calls.
		size := int(p.expo(float64(p.perTick)))
		if size < 1 {
			size = 1
		}
		mean := float64(p.tickSleep)
		if mean < float64(time.Millisecond) {
			mean = float64(time.Millisecond)
		}
		return Step{Size: size, Delay: p.JitterDelay(time.Duration(p.expo(mean)))}

	case PatternRamp:
		frac := float64(elapsed) / math.Max(float64(p.period), float64(time.Millisecond))
		frac = math.Max(0.1, math.Min(1.0, frac))
		size := int(float64(p.perTick) * frac)
		if size < 1 {
			size = 1
		}
		return Step{Size: size, Delay: p.JitterDelay(p.tickSleep)}

	default:
		return Step{Size: p.perTick, Delay: p.JitterDelay(p.tickSleep)}
	}
}

// expo draws from an exponential distribution with the given mean.
func (p *Pacer) expo(mean float64) float64 {
	if mean <= 0 {
		return 0
	}
	return p.rng.ExpFloat64() * mean
}

// Period is how long one send burst lasts.
func (p *Pacer) Period() time.Duration { return p.period }

// IdleBetweenPeriods reports whether the shape pauses between periods. Burst
// and periodic idle for one period; continuous, poisson and ramp chain sends
// back to back.
func (p *Pacer) IdleBetweenPeriods() bool {
	return p.pattern == PatternBurst || p.pattern == PatternPeriodic
}
