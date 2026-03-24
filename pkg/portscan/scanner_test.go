package portscan

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestScanFindsOpenPort(t *testing.T) {
	// Start a local TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	opts := Options{
		Timeout: 1 * time.Second,
		Workers: 10,
		Ports:   []int{port},
	}

	results := Scan(context.Background(), "127.0.0.1", opts)
	if len(results) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(results))
	}
	if results[0].Port != port {
		t.Errorf("expected port %d, got %d", port, results[0].Port)
	}
	if !results[0].Open {
		t.Error("expected port to be open")
	}
}

func TestScanClosedPort(t *testing.T) {
	opts := Options{
		Timeout: 500 * time.Millisecond,
		Workers: 1,
		Ports:   []int{1}, // port 1 is almost certainly closed
	}

	results := Scan(context.Background(), "127.0.0.1", opts)
	if len(results) != 0 {
		t.Errorf("expected 0 open ports, got %d", len(results))
	}
}

func TestScanContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	opts := Options{
		Timeout: 1 * time.Second,
		Workers: 10,
		Ports:   PortRange(1, 100),
	}

	results := Scan(ctx, "127.0.0.1", opts)
	// Should return quickly with few or no results
	_ = results
}

func TestPortRange(t *testing.T) {
	ports := PortRange(80, 85)
	if len(ports) != 6 {
		t.Errorf("expected 6 ports, got %d", len(ports))
	}
	if ports[0] != 80 || ports[5] != 85 {
		t.Errorf("unexpected range: %v", ports)
	}

	// Reversed
	ports = PortRange(85, 80)
	if len(ports) != 6 {
		t.Errorf("reversed: expected 6 ports, got %d", len(ports))
	}
}

func TestLookupService(t *testing.T) {
	if s := LookupService(22); s != "ssh" {
		t.Errorf("expected ssh, got %q", s)
	}
	if s := LookupService(99999); s != "" {
		t.Errorf("expected empty, got %q", s)
	}
}

func TestCommonPorts(t *testing.T) {
	ports := CommonPorts()
	if len(ports) == 0 {
		t.Error("CommonPorts should not be empty")
	}
}
