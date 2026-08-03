package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Flow is one sender or receiver role for the node this agent runs on. The
// planner writes these; the agent never decides what traffic exists.
type Flow struct {
	ID       string  `json:"id"`
	Role     string  `json:"role"`     // "sender" or "receiver"
	Protocol string  `json:"protocol"` // TCP or UDP
	Host     string  `json:"host"`     // destination IP (sender only)
	Port     int     `json:"port"`
	RateKbps float64 `json:"rate_kbps"`
	PeriodS  float64 `json:"period_s"`
	JitterP  float64 `json:"jitter_pct"`
	Pattern  string  `json:"pattern"`
	Content  string  `json:"content_type"`
	Seed     int64   `json:"seed"`
}

// Config is the per-node traffic definition written to
// /tmp/traffic/traffic_<node_id>.json.
type Config struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Seed     int64  `json:"seed"`
	Flows    []Flow `json:"flows"`
}

func (f Flow) IsSender() bool {
	return !strings.EqualFold(strings.TrimSpace(f.Role), "receiver")
}

func (f Flow) IsUDP() bool {
	return strings.EqualFold(strings.TrimSpace(f.Protocol), "udp")
}

// Label is used in logs and stats so a flow is identifiable without repeating
// its whole definition.
func (f Flow) Label() string {
	if strings.TrimSpace(f.ID) != "" {
		return f.ID
	}
	if f.IsSender() {
		return fmt.Sprintf("%s->%s:%d", strings.ToUpper(f.Protocol), f.Host, f.Port)
	}
	return fmt.Sprintf("%s listen :%d", strings.ToUpper(f.Protocol), f.Port)
}

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if len(cfg.Flows) == 0 {
		return nil, fmt.Errorf("config %s defines no flows", path)
	}
	for i := range cfg.Flows {
		if cfg.Flows[i].Port <= 0 || cfg.Flows[i].Port > 65535 {
			return nil, fmt.Errorf("flow %d has invalid port %d", i, cfg.Flows[i].Port)
		}
		if cfg.Flows[i].IsSender() && strings.TrimSpace(cfg.Flows[i].Host) == "" {
			return nil, fmt.Errorf("flow %d is a sender with no host", i)
		}
	}
	return cfg, nil
}
