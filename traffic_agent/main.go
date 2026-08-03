// Command traffic-agent generates the synthetic traffic a ScenarioForge
// scenario describes.
//
// It replaces the per-flow Python scripts that ran before. Those needed a
// python3 interpreter inside the node, which CORE vnodes have (they share the
// host filesystem) but most vulnerability container images do not, so traffic
// assigned to a Docker node silently never started. A single static binary runs
// everywhere: no interpreter, no package manager, no runtime downloads.
//
// One agent handles every flow for its node, each in its own goroutine with its
// own seeded RNG, and reports what it actually sent so a run can be verified
// rather than assumed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to the node's traffic config JSON")
	statsPath := flag.String("stats", "", "optional path to write periodic stats JSON")
	statsEvery := flag.Duration("stats-interval", 10*time.Second, "how often to write stats")
	duration := flag.Duration("duration", 0, "stop after this long (0 = run until signalled)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *configPath == "" {
		log.Fatal("traffic-agent: -config is required")
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("traffic-agent: %v", err)
	}

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix(fmt.Sprintf("[traffic-agent %s/%s] ", cfg.NodeName, cfg.NodeID))
	log.Printf("starting %d flow(s) from %s", len(cfg.Flows), *configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Terminate cleanly so CORE session teardown does not leave orphans.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signals
		log.Printf("received %s, stopping", sig)
		cancel()
	}()
	if *duration > 0 {
		go func() {
			select {
			case <-time.After(*duration):
				log.Printf("duration %s elapsed, stopping", *duration)
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	stats := NewStats()
	var wg sync.WaitGroup
	for i, flow := range cfg.Flows {
		// Each flow gets its own generator so one flow's draws cannot shift
		// another's, which keeps a seeded run reproducible.
		seed := flow.Seed
		if seed == 0 {
			seed = cfg.Seed + int64(i)*7919
		}
		rng := rand.New(rand.NewSource(seed))
		counter := stats.Register(flow.Label())

		wg.Add(1)
		go func(f Flow, r *rand.Rand, c *FlowCounter) {
			defer wg.Done()
			if f.IsSender() {
				runSender(ctx, f, r, c)
				return
			}
			runReceiver(ctx, f, c)
		}(flow, rng, counter)
	}

	if *statsPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writeStatsPeriodically(ctx, stats, *statsPath, *statsEvery)
		}()
	}

	wg.Wait()
	if *statsPath != "" {
		if err := stats.WriteFile(*statsPath); err != nil {
			log.Printf("failed writing final stats: %v", err)
		}
	}
	log.Printf("stopped; %s", stats.Summary())
}



// runSender drives one outbound flow until the context is cancelled. Connection
// errors are retried rather than fatal: a receiver may still be starting, and a
// scenario should converge instead of losing the flow on a startup race.
func runSender(ctx context.Context, flow Flow, rng *rand.Rand, counter *FlowCounter) {
	content := NormalizeContentType(flow.Content, rng)
	pacer := NewPacer(flow.Pattern, flow.RateKbps, flow.PeriodS, flow.JitterP, rng)
	builder := NewPayloadBuilder(content, rng)
	target := net.JoinHostPort(flow.Host, fmt.Sprintf("%d", flow.Port))

	log.Printf("sender %s: %s %s pattern=%s content=%s rate=%.1fkbps",
		flow.Label(), flow.Protocol, target, NormalizePattern(flow.Pattern), content, flow.RateKbps)

	for ctx.Err() == nil {
		sendOnePeriod(ctx, flow, pacer, builder, target, counter)
		if ctx.Err() != nil {
			return
		}
		if pacer.IdleBetweenPeriods() {
			sleepCtx(ctx, pacer.JitterDelay(pacer.Period()))
		}
	}
}

func sendOnePeriod(ctx context.Context, flow Flow, pacer *Pacer, builder *PayloadBuilder, target string, counter *FlowCounter) {
	network := "tcp"
	if flow.IsUDP() {
		network = "udp"
	}
	conn, err := net.DialTimeout(network, target, 2*time.Second)
	if err != nil {
		counter.AddError()
		// Back off briefly so an unreachable peer does not spin the CPU.
		sleepCtx(ctx, 1*time.Second)
		return
	}
	defer conn.Close()
	counter.AddConnection()

	start := time.Now()
	deadline := start.Add(pacer.Period())
	// Closed-loop pacing: schedule against a running deadline rather than
	// sleeping a fixed interval after each write. Sleeping post-write makes the
	// real period (work + sleep) longer than intended, so achieved throughput
	// drifts below the configured rate -- silently, which is what the previous
	// Python sender did. Advancing a target instant absorbs the write cost.
	next := start
	for time.Now().Before(deadline) && ctx.Err() == nil {
		step := pacer.Step(time.Since(start))
		payload := builder.Bytes(step.Size)
		if len(payload) > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Write(payload)
			if n > 0 {
				counter.AddSent(int64(n))
			}
			if err != nil {
				counter.AddError()
				return // reconnect on the next period
			}
		}
		next = next.Add(step.Delay)
		// If writes fell behind, catch up by sending again immediately rather
		// than accumulating unbounded debt.
		if wait := time.Until(next); wait > 0 {
			sleepCtx(ctx, wait)
		} else if wait < -time.Second {
			next = time.Now()
		}
	}
}

// runReceiver is the sink side. It accepts and discards, which is all the
// previous Python receivers did, but it also counts bytes so a flow can be
// verified from the destination as well as the source.
func runReceiver(ctx context.Context, flow Flow, counter *FlowCounter) {
	addr := fmt.Sprintf("0.0.0.0:%d", flow.Port)
	if flow.IsUDP() {
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			log.Printf("receiver %s: listen failed: %v", flow.Label(), err)
			counter.AddError()
			return
		}
		defer conn.Close()
		log.Printf("receiver %s: UDP listening on %s", flow.Label(), addr)
		buf := make([]byte, 65535)
		for ctx.Err() == nil {
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, _, err := conn.ReadFrom(buf)
			if n > 0 {
				counter.AddReceived(int64(n))
			}
			if err != nil && !isTimeout(err) && ctx.Err() == nil {
				counter.AddError()
			}
		}
		return
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("receiver %s: listen failed: %v", flow.Label(), err)
		counter.AddError()
		return
	}
	defer listener.Close()
	log.Printf("receiver %s: TCP listening on %s", flow.Label(), addr)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			counter.AddError()
			continue
		}
		counter.AddConnection()
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 32*1024)
			for ctx.Err() == nil {
				n, err := c.Read(buf)
				if n > 0 {
					counter.AddReceived(int64(n))
				}
				if err != nil {
					return
				}
			}
		}(conn)
	}
}

// isTimeout distinguishes the read deadline we set to stay cancellable from a
// real receive error, so idle receivers do not accumulate phantom errors.
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// sleepCtx waits for d, returning early if the context is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func writeStatsPeriodically(ctx context.Context, stats *Stats, path string, every time.Duration) {
	if every <= 0 {
		every = 10 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := stats.WriteFile(path); err != nil {
				log.Printf("failed writing stats: %v", err)
			}
		}
	}
}
