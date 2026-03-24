package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lybw/netkit/pkg/discovery"
	"github.com/lybw/netkit/pkg/fingerprint"
	"github.com/lybw/netkit/pkg/oui"
	"github.com/lybw/netkit/pkg/portscan"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx := context.Background()

	switch os.Args[1] {
	case "discover":
		cmdDiscover(ctx)
	case "portscan":
		cmdPortscan(ctx)
	case "oui":
		cmdOUI()
	case "fingerprint":
		cmdFingerprint(ctx)
	case "version":
		fmt.Printf("netkit %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`netkit - Network Operations Toolkit

Usage:
  netkit <command> [arguments]

Commands:
  discover <cidr>           Discover devices on a LAN (e.g., 192.168.1.0/24)
  portscan <host> [-p ports]  Scan TCP ports on a host
  oui <mac>                 Look up MAC address vendor
  fingerprint <host>        Detect OS via TTL analysis
  version                   Print version
  help                      Show this help

Examples:
  netkit discover 192.168.1.0/24
  netkit portscan 192.168.1.1 -p 22,80,443
  netkit oui 00:0C:29:AA:BB:CC
  netkit fingerprint 192.168.1.1
`)
}

func cmdDiscover(ctx context.Context) {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: netkit discover <cidr>")
		os.Exit(1)
	}

	cidr := os.Args[2]
	fmt.Printf("Scanning %s ...\n\n", cidr)

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	devices, err := discovery.ARP(ctx, cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%-16s %-18s %s\n", "IP", "MAC", "VENDOR")
	fmt.Printf("%-16s %-18s %s\n", "──────────────", "─────────────────", "──────────────")
	for _, d := range devices {
		vendor := oui.Lookup(d.MAC)
		fmt.Printf("%-16s %-18s %s\n", d.IP, d.MAC, vendor)
	}
	fmt.Printf("\n%d device(s) found.\n", len(devices))
}

func cmdPortscan(ctx context.Context) {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: netkit portscan <host> [-p ports]")
		os.Exit(1)
	}

	host := os.Args[2]
	opts := portscan.DefaultOptions()

	// Parse -p flag
	for i := 3; i < len(os.Args); i++ {
		if os.Args[i] == "-p" && i+1 < len(os.Args) {
			ports, err := parsePorts(os.Args[i+1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid ports: %v\n", err)
				os.Exit(1)
			}
			opts.Ports = ports
			i++
		}
	}

	fmt.Printf("Scanning %s (%d ports) ...\n\n", host, len(opts.Ports))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	start := time.Now()
	results := portscan.Scan(ctx, host, opts)
	elapsed := time.Since(start)

	fmt.Printf("%-8s %-8s %-12s %s\n", "PORT", "STATE", "SERVICE", "LATENCY")
	fmt.Printf("%-8s %-8s %-12s %s\n", "────", "─────", "───────", "───────")
	for _, r := range results {
		fmt.Printf("%-8d %-8s %-12s %s\n", r.Port, "open", r.Service, r.Latency.Round(time.Millisecond))
	}
	fmt.Printf("\n%d open port(s) found in %s.\n", len(results), elapsed.Round(time.Millisecond))
}

func cmdOUI() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: netkit oui <mac>")
		os.Exit(1)
	}

	mac := os.Args[2]
	vendor := oui.Lookup(mac)
	fmt.Printf("%s -> %s\n", mac, vendor)
}

func cmdFingerprint(ctx context.Context) {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: netkit fingerprint <host>")
		os.Exit(1)
	}

	host := os.Args[2]
	fmt.Printf("Fingerprinting %s ...\n\n", host)

	guess, err := fingerprint.DetectByTTL(host, 3*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OS:         %s\n", guess.OS)
	fmt.Printf("Confidence: %d%%\n", guess.Confidence)
	fmt.Printf("TTL:        %d\n", guess.TTL)
	fmt.Printf("Method:     %s\n", guess.Method)
}

// parsePorts parses a port specification like "22,80,443" or "1-1024".
func parsePorts(spec string) ([]int, error) {
	var ports []int
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", bounds[0])
			}
			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", bounds[1])
			}
			ports = append(ports, portscan.PortRange(start, end)...)
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}
