package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

// freePort returns a port that is free right now, plus a listener holding it so
// the caller decides when to release it.
func occupiedPort(t *testing.T) (int, net.Listener) {
	t.Helper()
	// Bind the wildcard address: that is what the receiver binds, so holding
	// only 127.0.0.1 would not collide with it.
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return l.Addr().(*net.TCPAddr).Port, l
}

// A receiver whose bind fails must keep trying: the node's interface may still
// be coming up, or an earlier agent may not have released the port yet. Giving
// up leaves the flow permanently dead while the sender retries forever.
func TestReceiverRetriesListenUntilPortIsFree(t *testing.T) {
	port, blocker := occupiedPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	counter := &FlowCounter{label: "test-rx"}
	flow := Flow{ID: "test-rx", Role: "receiver", Protocol: "TCP", Port: port}
	done := make(chan struct{})
	go func() {
		runReceiver(ctx, flow, counter)
		close(done)
	}()

	// The first bind attempt loses the port, and the receiver must survive it.
	time.Sleep(300 * time.Millisecond)
	if counter.errors.Load() == 0 {
		t.Fatal("expected the blocked bind to be recorded as an error")
	}
	_ = blocker.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("receiver never bound %s after the port was released: %v", addr, err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.Close()

	for time.Now().Before(deadline) {
		if counter.bytesRecv.Load() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if counter.bytesRecv.Load() == 0 {
		t.Fatal("receiver bound but counted no bytes")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not stop on cancel")
	}
}

// The UDP receiver has the same obligation, and its listener is bound the same
// way, so a busy port must not end the flow either.
func TestUDPReceiverRetriesListen(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	// Hold the exact address the receiver binds so the first attempt fails.
	blocker, err := net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", port))
	_ = pc.Close()
	if err != nil {
		t.Skipf("cannot reserve 0.0.0.0:%d: %v", port, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	counter := &FlowCounter{label: "test-udp-rx"}
	flow := Flow{ID: "test-udp-rx", Role: "receiver", Protocol: "UDP", Port: port}
	go runReceiver(ctx, flow, counter)

	time.Sleep(300 * time.Millisecond)
	if counter.errors.Load() == 0 {
		t.Fatal("expected the blocked UDP bind to be recorded as an error")
	}
	_ = blocker.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && counter.bytesRecv.Load() == 0 {
		if c, derr := net.Dial("udp", addr); derr == nil {
			_, _ = c.Write([]byte("hello"))
			_ = c.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	if counter.bytesRecv.Load() == 0 {
		t.Fatal("UDP receiver never bound after the port was released")
	}
}

// A sender whose destination is not reachable yet must keep dialing rather than
// exiting, so a flow starts as soon as routing converges.
func TestSenderKeepsRetryingUnreachableDestination(t *testing.T) {
	port, blocker := occupiedPort(t)
	_ = blocker.Close() // nothing listens here now

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	counter := &FlowCounter{label: "test-tx"}
	flow := Flow{ID: "test-tx", Role: "sender", Protocol: "TCP",
		Host: "127.0.0.1", Port: port, RateKbps: 8, PeriodS: 0.2}
	rng := rand.New(rand.NewSource(1))

	done := make(chan struct{})
	go func() {
		runSender(ctx, flow, rng, counter)
		close(done)
	}()

	// Start listening late; the sender must find it without being restarted.
	time.Sleep(1500 * time.Millisecond)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("late listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		accepted <- struct{}{}
		buf := make([]byte, 4096)
		for {
			if _, rerr := c.Read(buf); rerr != nil {
				return
			}
		}
	}()

	select {
	case <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("sender never connected after the destination came up")
	}

	<-done
	if counter.errors.Load() == 0 {
		t.Fatal("expected the early dial failures to be counted")
	}
	if counter.bytesSent.Load() == 0 {
		t.Fatal("sender connected but sent nothing")
	}
}

func TestRetryDelayIsBoundedAndNeverZero(t *testing.T) {
	if got := retryDelay(0); got != time.Second {
		t.Fatalf("retryDelay(0) = %s, want 1s", got)
	}
	if got := retryDelay(3); got != 3*time.Second {
		t.Fatalf("retryDelay(3) = %s, want 3s", got)
	}
	if got := retryDelay(1000); got != 15*time.Second {
		t.Fatalf("retryDelay(1000) = %s, want the 15s cap", got)
	}
}
