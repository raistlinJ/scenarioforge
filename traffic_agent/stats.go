package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// FlowCounter records what one flow actually moved. The previous scripts were
// silent, so a flow that never connected looked identical to one running
// perfectly; these counters let a run be verified instead of assumed.
type FlowCounter struct {
	label       string
	bytesSent   atomic.Int64
	bytesRecv   atomic.Int64
	connections atomic.Int64
	errors      atomic.Int64
}

func (c *FlowCounter) AddSent(n int64)     { c.bytesSent.Add(n) }
func (c *FlowCounter) AddReceived(n int64) { c.bytesRecv.Add(n) }
func (c *FlowCounter) AddConnection()      { c.connections.Add(1) }
func (c *FlowCounter) AddError()           { c.errors.Add(1) }

type flowSnapshot struct {
	Flow          string  `json:"flow"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesReceived int64   `json:"bytes_received"`
	Connections   int64   `json:"connections"`
	Errors        int64   `json:"errors"`
	AchievedKbps  float64 `json:"achieved_kbps"`
}

type statsSnapshot struct {
	StartedAt   string         `json:"started_at"`
	UpdatedAt   string         `json:"updated_at"`
	ElapsedS    float64        `json:"elapsed_s"`
	TotalSent   int64          `json:"total_bytes_sent"`
	TotalRecv   int64          `json:"total_bytes_received"`
	TotalErrors int64          `json:"total_errors"`
	Flows       []flowSnapshot `json:"flows"`
}

type Stats struct {
	mu      sync.Mutex
	started time.Time
	flows   []*FlowCounter
}

func NewStats() *Stats {
	return &Stats{started: time.Now()}
}

func (s *Stats) Register(label string) *FlowCounter {
	s.mu.Lock()
	defer s.mu.Unlock()
	counter := &FlowCounter{label: label}
	s.flows = append(s.flows, counter)
	return counter
}

func (s *Stats) snapshot() statsSnapshot {
	s.mu.Lock()
	flows := make([]*FlowCounter, len(s.flows))
	copy(flows, s.flows)
	started := s.started
	s.mu.Unlock()

	elapsed := time.Since(started).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	out := statsSnapshot{
		StartedAt: started.UTC().Format(time.RFC3339),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		ElapsedS:  round3(elapsed),
	}
	for _, f := range flows {
		sent := f.bytesSent.Load()
		recv := f.bytesRecv.Load()
		out.TotalSent += sent
		out.TotalRecv += recv
		out.TotalErrors += f.errors.Load()
		// Reported so a scenario can be checked against the rate it asked for,
		// rather than trusting that the configured rate was achievable.
		moved := sent
		if moved == 0 {
			moved = recv
		}
		out.Flows = append(out.Flows, flowSnapshot{
			Flow:          f.label,
			BytesSent:     sent,
			BytesReceived: recv,
			Connections:   f.connections.Load(),
			Errors:        f.errors.Load(),
			AchievedKbps:  round3(float64(moved) / 1024.0 / elapsed),
		})
	}
	return out
}

// WriteFile persists the current counters atomically, so a reader never sees a
// half-written file.
func (s *Stats) WriteFile(path string) error {
	payload, err := json.MarshalIndent(s.snapshot(), "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Stats) Summary() string {
	snap := s.snapshot()
	return fmt.Sprintf("sent=%dB received=%dB errors=%d over %.1fs",
		snap.TotalSent, snap.TotalRecv, snap.TotalErrors, snap.ElapsedS)
}

func round3(v float64) float64 {
	return float64(int64(v*1000+0.5)) / 1000.0
}
