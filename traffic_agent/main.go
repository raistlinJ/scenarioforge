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
// errors are retried rather than fatal: a receiver may still be starting, a
// routing protocol may not have converged yet, and a scenario should converge
// instead of losing the flow on a startup race. There is no attempt limit --
// OSPF adjacency on a large topology can take minutes, and a sender that gave
// up would leave a permanently dead flow behind a network that later works.
func runSender(ctx context.Context, flow Flow, rng *rand.Rand, counter *FlowCounter) {
	content := NormalizeContentType(flow.Content, rng)
	pacer := NewPacer(flow.Pattern, flow.RateKbps, flow.PeriodS, flow.JitterP, rng)
	builder := NewPayloadBuilder(content, rng)
	target := net.JoinHostPort(flow.Host, fmt.Sprintf("%d", flow.Port))

	log.Printf("sender %s: %s %s pattern=%s content=%s rate=%.1fkbps",
		flow.Label(), flow.Protocol, target, NormalizePattern(flow.Pattern), content, flow.RateKbps)

	// Report the first failure, then only transitions and occasional progress:
	// a flow waiting out route convergence must not fill the node's log.
	failures := 0
	for ctx.Err() == nil {
		err := sendOnePeriod(ctx, flow, pacer, builder, target, counter)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
			if failures == 1 || failures%30 == 0 {
				log.Printf("sender %s: cannot reach %s (attempt %d): %v; still retrying",
					flow.Label(), target, failures, err)
			}
			// Back off briefly so an unreachable peer does not spin the CPU.
			sleepCtx(ctx, retryDelay(failures))
			continue
		}
		if failures > 0 {
			log.Printf("sender %s: connected to %s after %d failed attempt(s)",
				flow.Label(), target, failures)
			failures = 0
		}
		if pacer.IdleBetweenPeriods() {
			sleepCtx(ctx, pacer.JitterDelay(pacer.Period()))
		}
	}
}

// sendOnePeriod runs one send period, returning the dial error when the peer
// could not be reached at all. A mid-period write error is not returned: the
// connection was established, so the next period simply reconnects.
func sendOnePeriod(ctx context.Context, flow Flow, pacer *Pacer, builder *PayloadBuilder, target string, counter *FlowCounter) error {
	network := "tcp"
	if flow.IsUDP() {
		network = "udp"
	}
	conn, err := net.DialTimeout(network, target, 2*time.Second)
	if err != nil {
		counter.AddError()
		return err
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
				return nil // reconnect on the next period
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
	return nil
}

// runReceiver is the sink side. It accepts and discards, which is all the
// previous Python receivers did, but it also counts bytes so a flow can be
// verified from the destination as well as the source.
//
// Listening is retried for the whole life of the run, exactly like the sender's
// dial. A bind can fail for reasons that clear on their own -- the node's
// interface is still coming up, or a previous agent has not released the port
// yet -- and returning on the first error killed the flow permanently: the
// sender then retried forever against a node that would never listen again,
// which reads as an unreachable destination rather than a dead receiver.
func runReceiver(ctx context.Context, flow Flow, counter *FlowCounter) {
	addr := fmt.Sprintf("0.0.0.0:%d", flow.Port)
	failures := 0
	for ctx.Err() == nil {
		var err error
		started := time.Now()
		if flow.IsUDP() {
			err = serveUDP(ctx, flow, addr, counter)
		} else {
			err = serveTCP(ctx, flow, addr, counter)
		}
		if ctx.Err() != nil {
			return
		}
		// A listener that held the port for a while and then broke is a fresh
		// problem, not a continuing one: start its backoff over.
		if time.Since(started) > 30*time.Second {
			failures = 0
		}
		failures++
		counter.AddError()
		if failures == 1 || failures%30 == 0 {
			log.Printf("receiver %s: listen on %s failed (attempt %d): %v; still retrying",
				flow.Label(), addr, failures, err)
		}
		sleepCtx(ctx, retryDelay(failures))
	}
}

// serveUDP owns one UDP listener until it dies or the run ends. It returns the
// error that ended it so the caller can listen again.
func serveUDP(ctx context.Context, flow Flow, addr string, counter *FlowCounter) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("receiver %s: UDP listening on %s", flow.Label(), addr)

	buf := make([]byte, 65535)
	consecutive := 0
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if n > 0 {
			counter.AddReceived(int64(n))
		}
		if err == nil || isTimeout(err) {
			consecutive = 0
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		counter.AddError()
		consecutive++
		// A socket that keeps erroring is not going to recover by being read
		// again; hand it back so a fresh one is bound.
		if consecutive >= 10 {
			return err
		}
	}
	return nil
}

// serveTCP owns one TCP listener until it dies or the run ends.
func serveTCP(ctx context.Context, flow Flow, addr string, counter *FlowCounter) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("receiver %s: TCP listening on %s", flow.Label(), addr)

	// Unblock Accept when the run ends.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()

	consecutive := 0
	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			counter.AddError()
			consecutive++
			if consecutive >= 10 {
				return err
			}
			// Never spin: a transient accept error (fd exhaustion, a peer that
			// vanished mid-handshake) must not burn the node's CPU.
			sleepCtx(ctx, 200*time.Millisecond)
			continue
		}
		consecutive = 0
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
	return nil
}

// retryDelay backs a repeatedly failing endpoint off from 1s to 15s. The cap
// stays low on purpose: these retries are waiting for a network to converge,
// and a flow should start moving within seconds of it doing so.
func retryDelay(failures int) time.Duration {
	d := time.Duration(failures) * time.Second
	if d < 1*time.Second {
		d = 1 * time.Second
	}
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	return d
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
