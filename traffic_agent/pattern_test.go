package main

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

func TestNormalizePattern(t *testing.T) {
	cases := map[string]string{
		"poisson": PatternPoisson, "POISSON": PatternPoisson,
		"ramp": PatternRamp, "burst": PatternBurst, "periodic": PatternPeriodic,
		"continuous": PatternContinuous, "": PatternContinuous, "nonsense": PatternContinuous,
	}
	for input, want := range cases {
		if got := NormalizePattern(input); got != want {
			t.Fatalf("NormalizePattern(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestOnlyBurstAndPeriodicIdleBetweenPeriods(t *testing.T) {
	idle := map[string]bool{
		PatternBurst: true, PatternPeriodic: true,
		PatternContinuous: false, PatternPoisson: false, PatternRamp: false,
	}
	for pattern, want := range idle {
		p := NewPacer(pattern, 64, 1, 0, newRNG())
		if got := p.IdleBetweenPeriods(); got != want {
			t.Fatalf("%s IdleBetweenPeriods() = %v, want %v", pattern, got, want)
		}
	}
}

func TestRateConvertsToPerTickBytes(t *testing.T) {
	// 1024 kbps -> 1024*1024 bytes/s spread across the tick rate.
	p := NewPacer(PatternContinuous, 1024, 1, 0, newRNG())
	want := 1024 * 1024 / ticksPerSecond
	if p.Step(0).Size != want {
		t.Fatalf("per-tick size = %d, want %d", p.Step(0).Size, want)
	}
}

func TestZeroRateFallsBackToSmallDefault(t *testing.T) {
	// The Python sender defaulted to ~1KiB/s when a flow gave no rate.
	p := NewPacer(PatternContinuous, 0, 1, 0, newRNG())
	if got := p.Step(0).Size; got < 1 {
		t.Fatalf("zero rate should still send something, got %d", got)
	}
}

func TestRampScalesFromTenPercentToFull(t *testing.T) {
	period := 10.0
	p := NewPacer(PatternRamp, 1024, period, 0, newRNG())
	full := 1024 * 1024 / ticksPerSecond

	atStart := p.Step(0).Size
	atEnd := p.Step(time.Duration(period * float64(time.Second))).Size

	if atStart > full/5 {
		t.Fatalf("ramp should start near 10%% of %d, got %d", full, atStart)
	}
	if atEnd != full {
		t.Fatalf("ramp should reach the full per-tick size %d, got %d", full, atEnd)
	}
	if atStart >= atEnd {
		t.Fatalf("ramp should increase over the period (%d -> %d)", atStart, atEnd)
	}
}

func TestJitterStaysWithinConfiguredBand(t *testing.T) {
	p := NewPacer(PatternContinuous, 64, 1, 50, rand.New(rand.NewSource(1)))
	base := 100 * time.Millisecond
	for i := 0; i < 500; i++ {
		got := p.JitterDelay(base)
		if got < 50*time.Millisecond || got > 150*time.Millisecond {
			t.Fatalf("50%% jitter on 100ms produced %v, outside [50ms,150ms]", got)
		}
	}
}

func TestZeroJitterIsExact(t *testing.T) {
	p := NewPacer(PatternContinuous, 64, 1, 0, newRNG())
	base := 25 * time.Millisecond
	if got := p.JitterDelay(base); got != base {
		t.Fatalf("zero jitter should not alter the delay: got %v", got)
	}
}

func TestJitterNeverNegative(t *testing.T) {
	// Jitter above 100% would push a naive implementation below zero.
	p := NewPacer(PatternContinuous, 64, 1, 300, rand.New(rand.NewSource(3)))
	for i := 0; i < 500; i++ {
		if got := p.JitterDelay(10 * time.Millisecond); got < 0 {
			t.Fatalf("jitter produced a negative delay: %v", got)
		}
	}
}

func TestPoissonInterArrivalAveragesNearTheTickInterval(t *testing.T) {
	// Exponential draws should centre on the tick interval; this is the
	// property that makes poisson traffic look bursty but rate-correct.
	p := NewPacer(PatternPoisson, 1024, 5, 0, rand.New(rand.NewSource(11)))
	const n = 20000
	var total float64
	for i := 0; i < n; i++ {
		total += float64(p.Step(0).Delay)
	}
	mean := total / n
	expected := float64(p.tickSleep)
	if math.Abs(mean-expected)/expected > 0.1 {
		t.Fatalf("poisson mean delay %.0fns differs from tick %.0fns by >10%%", mean, expected)
	}
}

func TestPoissonSizesVaryButStayPositive(t *testing.T) {
	p := NewPacer(PatternPoisson, 1024, 5, 0, rand.New(rand.NewSource(5)))
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		size := p.Step(0).Size
		if size < 1 {
			t.Fatalf("poisson produced a non-positive size: %d", size)
		}
		seen[size] = true
	}
	if len(seen) < 10 {
		t.Fatalf("poisson sizes should vary, saw only %d distinct values", len(seen))
	}
}

func TestPeriodDefaultsWhenUnset(t *testing.T) {
	p := NewPacer(PatternContinuous, 64, 0, 0, newRNG())
	if p.Period() != time.Duration(defaultPeriodSeconds*float64(time.Second)) {
		t.Fatalf("unset period should fall back to %.0fs, got %v", defaultPeriodSeconds, p.Period())
	}
}

func TestPacingIsFinerThanTheOldPythonSender(t *testing.T) {
	// The Python implementation was pinned to 20 ticks/sec by interpreter
	// overhead, which turned a high-rate flow into visible bursts.
	if ticksPerSecond <= 20 {
		t.Fatalf("agent should pace finer than the 20Hz Python sender, got %d", ticksPerSecond)
	}
}
