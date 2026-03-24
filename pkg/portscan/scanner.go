// Package portscan provides a concurrent TCP port scanner.
package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Result represents a single port scan result.
type Result struct {
	Port    int
	Open    bool
	Service string
	Latency time.Duration
}

// Options configures the port scanner.
type Options struct {
	Timeout    time.Duration
	Workers    int
	Ports      []int
}

// DefaultOptions returns sensible default scan options.
func DefaultOptions() Options {
	return Options{
		Timeout: 2 * time.Second,
		Workers: 100,
		Ports:   CommonPorts(),
	}
}

// Scan performs a concurrent TCP connect scan on the target host.
func Scan(ctx context.Context, host string, opts Options) []Result {
	if opts.Workers <= 0 {
		opts.Workers = 100
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}

	var (
		mu      sync.Mutex
		results []Result
		wg      sync.WaitGroup
		sem     = make(chan struct{}, opts.Workers)
	)

	for _, port := range opts.Ports {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			r := scanPort(ctx, host, p, opts.Timeout)
			if r.Open {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}

func scanPort(ctx context.Context, host string, port int, timeout time.Duration) Result {
	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)

	r := Result{
		Port:    port,
		Service: LookupService(port),
	}

	if err != nil {
		r.Open = false
		return r
	}
	conn.Close()

	r.Open = true
	r.Latency = time.Since(start)
	return r
}

// CommonPorts returns a list of commonly scanned ports.
func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 445, 993, 995, 1433, 1521, 1723,
		3306, 3389, 5432, 5900, 5901, 6379, 8000,
		8080, 8443, 8888, 9090, 9200, 27017,
	}
}

// PortRange generates a slice of ports from start to end (inclusive).
func PortRange(start, end int) []int {
	if start > end {
		start, end = end, start
	}
	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports
}

// LookupService returns the common service name for a port.
func LookupService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 111: "rpc",
		135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
		445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
		1521: "oracle", 1723: "pptp", 3306: "mysql", 3389: "rdp",
		5432: "postgres", 5900: "vnc", 5901: "vnc", 6379: "redis",
		8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
		8888: "http-alt", 9090: "prometheus", 9200: "elasticsearch",
		27017: "mongodb",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return ""
}
